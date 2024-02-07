
rule Trojan_Win32_ETWKeyLogger_ibt{
	meta:
		description = "Trojan:Win32/ETWKeyLogger!ibt,SIGNATURE_TYPE_PEHSTR,06 00 06 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 36 44 41 35 39 32 44 2d 45 34 33 41 2d 34 45 32 38 2d 41 46 36 46 2d 34 42 43 35 37 43 35 41 31 31 45 38 } //01 00  36DA592D-E43A-4E28-AF6F-4BC57C5A11E8
		$a_01_1 = {43 38 38 41 34 45 46 35 2d 44 30 34 38 2d 34 30 31 33 2d 39 34 30 38 2d 45 30 34 42 37 44 42 32 38 31 34 41 } //01 00  C88A4EF5-D048-4013-9408-E04B7DB2814A
		$a_01_2 = {45 54 57 54 72 61 63 65 45 76 65 6e 74 53 6f 75 72 63 65 } //01 00  ETWTraceEventSource
		$a_01_3 = {66 69 64 5f 55 52 42 5f 54 72 61 6e 73 66 65 72 42 75 66 66 65 72 4c 65 6e 67 74 68 } //01 00  fid_URB_TransferBufferLength
		$a_01_4 = {61 64 64 5f 43 61 6e 63 65 6c 4b 65 79 50 72 65 73 73 } //01 00  add_CancelKeyPress
		$a_01_5 = {69 73 43 74 72 6c 43 45 78 65 63 75 74 65 64 } //01 00  isCtrlCExecuted
		$a_01_6 = {66 69 64 5f 55 53 42 50 4f 52 54 5f 55 52 42 5f 42 55 4c 4b 5f 4f 52 5f 49 4e 54 45 52 52 55 50 54 5f 54 52 41 4e 53 46 45 52 } //01 00  fid_USBPORT_URB_BULK_OR_INTERRUPT_TRANSFER
		$a_01_7 = {3c 53 74 61 72 74 44 75 6d 70 4b 65 79 73 3e } //03 00  <StartDumpKeys>
		$a_01_8 = {55 53 42 20 4b 65 79 6c 6f 67 67 65 72 20 75 73 69 6e 67 20 45 76 65 6e 74 20 54 72 61 63 69 6e 67 20 66 6f 72 20 57 69 6e 64 6f 77 73 } //01 00  USB Keylogger using Event Tracing for Windows
		$a_01_9 = {69 67 6e 6f 72 69 6e 67 20 6e 6f 6e 2d 75 73 62 20 6b 65 79 62 6f 61 72 64 20 64 65 76 69 63 65 3a 20 30 78 7b 30 3a 58 } //00 00  ignoring non-usb keyboard device: 0x{0:X
	condition:
		any of ($a_*)
 
}