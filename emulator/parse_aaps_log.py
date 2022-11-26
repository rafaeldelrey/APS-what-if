def scanLogfile(fn, entries):
    global SMBreason
    global xyf
    global fn_base  # keep first match in case of wild card file list
    global log
    global varlog
    global newLoop
    global dataType_offset, AAPS_Version
    global CarbReqGram, CarbReqTime, lastCOB

    if not newLoop:  # otherwise continued from provious logfile
        SMBreason = {}
        SMBreason['script'] = '---------- Script Debug --------------------\n'
        # dataType_offset = 1                    #################### used for V2.6.1
    if filecount == 0:  # initalize file loop
        dataType_offset = -999  # AAPS version not yet known
        AAPS_Version = '<2.7'
        # fn_base=      fn + '.' + varLabel
        xyf = open(fn_first + '.' + varLabel + '.csv', 'w')
        log = open(fn_first + '.orig.txt', 'w')
        varlog = open(fn_first + '.' + varLabel + '.log', 'w')
        varlog.write(echo_msg)
    varlog.write(
        '\n========== Echo of what-if definitions actioned for variant ' + varLabel + '\n========== created on ' + formatdate(
            localtime=True) + '\n========== for loop events found in logfile ' + fn + '\n')
    log.write('AAPS scan from AAPS Logfile for SMB comparison created on ' + formatdate(localtime=True) + '\n')
    log.write('FILE=' + fn + '\n')
    global lcount
    # isZip = True    # testwise fix
    lcount = 0
    if isZip:
        with zipfile.ZipFile(fn) as z:
            for filename in z.namelist():
                lf = z.open(filename)  # has only 1 member file
    else:
        lf = open(fn, 'r')
    # lf = open(fn, 'r')
    notEOF = True  # needed because "for zeile in lf" does not work with AAPS 2.5

    cont = 'MORE'  # in case nothing found
    while notEOF:  # needed because "for zeile in lf" does not work with AAPS 2.5
        try:  # needed because "for zeile in lf" does not work with AAPS 2.5
            while True:
                try:
                    zeile = lf.readline()  # needed because "for zeile in lf" does not work with AAPS 2.5
                    break
                except FileNotFoundError:
                    log_msg('waiting 10s for logfile housekeeping')
                    time.sleep(10)
            if isZip:   zeile = str(zeile)[2:-3]  # strip off the "'b....'\n" remaining from the bytes to str conversion
            if zeile == '':  # needed because "for zeile in lf" does not work with AAPS 2.5
                notEOF = False  # needed because "for zeile in lf" does not work with AAPS 2.5
                break  # needed because "for zeile in lf" does not work with AAPS 2.5
            lcount += 1
            # print(zeile)
            if lcount > 100000:
                print('no end found at row ' + str(lcount) + ' reading /' + zeile + '/')
                return 'STOP'
            if len(zeile) > 13:
                headerKey = zeile[2] + zeile[5] + zeile[8] + zeile[12]
                if headerKey == '::. ':
                    sLine = zeile[13:]
                    Action = hole(sLine, 0, '[', ']')
                    sOffset = len(Action)
                    Block2 = hole(sLine, 1 + sOffset, '[', ']')
                    if Block2 == '[DataService.onHandleIntent():54]' \
                            or Block2 == '[DataService.onHandleIntent():55]' \
                            or Block2 == '[DataService.onHandleIntent():69]':  # token :54 added for AAPS versions <2.7, :69 for V2.7
                        pass
                    elif Block2[:-3] == '[DetermineBasalAdapterAMAJS.invoke():':  # various input items for loop
                        log_msg('\nSorry, this tool is currently only available for oref1 with SMB\n')
                        return 'STOP'
                    elif Block2.find('[DetermineBasalAdapterSMBJS.invoke():') == 0:  # loop inputs or result record
                        key_anf = Block2.find('):')
                        key_end = Block2.find(']:')
                        dataType = eval(Block2[key_anf + 2:key_end])
                        dataStr = sLine[sLine.find(']: ') + 3:]
                        dataTxt = dataStr[:17]  # make it dataTxt based rather than dataType (more robust)
                        if dataType_offset < -99:  # not yet initialized for known AAPS version
                            if dataType == 75:  # V 2.3 ?
                                log_msg('\nSorry, cannot extract required data from logfiles before AAPS version 2.5\n')
                                return 'STOP'
                            dataType_offset = dataType - 79  # "0" was lowest in V2.5.1
                            if dataType_offset >= 15:
                                AAPS_Version = '2.7'  # same as 2.8
                            elif dataType_offset < 0:
                                AAPS_Version = '2.7'  # same as 3.0
                            # elif dataType == 79:    dataType_offset =  0    # V 2.5.1
                            # elif dataType == 80:    dataType_offset =  1    # V 2.6.1
                            # elif dataType == 94:    dataType_offset = 15    # V 2.8.0    >>> Invoking detemine_basal <<< / Wolfgang Spänle
                            # elif dataType == 98:    dataType_offset = 19    # V 2.8.0    >>> Invoking detemine_basal <<< / Phillip
                            # elif dataType == 97:
                            #                        dataType_offset = 18    # V 2.7
                            #                        AAPS_Version = '2.7'
                            # elif dataType == 108:   pass                    # V 2 7:     MicroBolusAllowed:  true
                            # elif dataType == 109:   pass                    # V 2 7:     SMBAlwaysAllowed:  true
                            # elif dataType == 110:   pass                    # V 2 7:     CurrentTime: 1604776609511
                            # elif dataType != 163:   print('unhandled dataType:', str(dataType), 'row', str(lcount), 'of file',fn) # any but 2.7 RESULT
                            # version_set = True                              # keep until next logfile is loaded
                            pass
                        # elif Block2[:-4] == '[DetermineBasalAdapterSMBJS.invoke():':  # various input items for loop
                        # print (str(lcount), str(dataType), str(dataType_offset), dataTxt + dataStr[17:60])
                        if dataTxt[:16] == 'RhinoException: ':
                            code_error(lcount, dataStr)
                        elif dataTxt == 'Glucose status: {':
                            get_glucose_status(lcount, dataStr)
                        elif dataTxt == 'IOB data:       [':
                            get_iob_data(lcount, dataStr, log)
                        elif dataTxt == 'Current temp:   {':
                            get_currenttemp(lcount, dataStr)
                        elif dataTxt == 'Profile:        {':
                            get_profile(lcount, dataStr)
                        elif dataTxt == 'Meal data:      {':
                            get_meal_data(lcount, dataStr)
                        elif dataTxt == 'Autosens data:  {':
                            get_autosens_data(lcount, dataStr)
                        elif dataTxt == 'MicroBolusAllowed':
                            get_MicroBolusAllowed(lcount, dataStr)
                        elif dataTxt == 'Result: {"temp":"':
                            checkCarbsNeeded(dataStr[8:], lcount)  # result record in AAPS2.6.1
                            cont = TreatLoop(dataStr[8:], log, lcount)
                            if cont == 'STOP' or cont == 'SYNTAX':     return cont
                        # elif dataType == dataType_offset+145:               checkCarbsNeeded(dataStr[8:], lcount)   # result record in AAPS2.7
                        # elif dataType == dataType_offset+147:               checkCarbsNeeded(dataStr[8:], lcount)   # result record in AAPS2.8 Wolfgang Spänle
                        # elif dataType == dataType_offset+146:               checkCarbsNeeded(dataStr[8:], lcount)   # result record in AAPS2.8 / Phillip
                        pass
                    elif Block2 == '[LoggerCallback.jsFunction_log():39]' \
                            or Block2 == '[LoggerCallback.jsFunction_log():42]' \
                            or Block2 == '[LoggerCallback.jsFunction_log():21]':  # from console.error; '42' is for >= V2.7, '21' for V3
                        PrepareSMB(sLine, log, lcount)
                    elif Block2 == '[DbLogger.dbAdd():29]':  ################## flag for V2.5.1
                        Curly = hole(sLine, 1 + sOffset + len(Block2), '{', '}')
                        # print('calling TreatLoop in row '+str(lcount)+' with\n'+Curly)
                        if Curly.find('{"device":"openaps:') == 0:
                            cont = TreatLoop(Curly, log, lcount)
                            if cont == 'STOP' or cont == 'SYNTAX':     return cont
                    elif zeile.find('[NSClientPlugin.onStart$lambda-5():124]') > 0:  ################## flag for V3.0dev
                        Curly = hole(zeile, 5, '{', '}')
                        # print('calling TreatLoop in row '+str(lcount)+' with\n'+Curly)
                        # if  Curly.find('{"device":"openaps:')==0 \
                        # and Curly.find('"openaps":{"suggested":{')>0 :
                        if Curly.find('"openaps":{"suggested":{') > 0:
                            # and 'lastTempAge' in SMBreason :
                            cont = TreatLoop(Curly, log, lcount)
                            if cont == 'STOP' or cont == 'SYNTAX':     return cont
                elif zeile.find('data:{"device":"openaps:') == 0:  ################## flag for V2.6.1 ff
                    Curly = hole(zeile, 5, '{', '}')
                    # print('calling TreatLoop in row '+str(lcount)+' with\n'+Curly)
                    if Curly.find('{"device":"openaps:') == 0 \
                            and Curly.find('"openaps":{"suggested":{') > 0:
                        # and 'lastTempAge' in SMBreason :
                        cont = TreatLoop(Curly, log, lcount)
                        if cont == 'STOP' or cont == 'SYNTAX':     return cont

        except UnicodeDecodeError:  # needed because "for zeile in lf" does not work with AAPS 2.5 containing non-printing ASCII codes
            lcount += 1  # skip this line, it contains non-ASCII characters!

    lf.close()
    return cont