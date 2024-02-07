
rule Trojan_Win32_keyLogger_DJ_MTB{
	meta:
		description = "Trojan:Win32/keyLogger.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //01 00  Go build ID:
		$a_01_1 = {6b 6c 6f 67 67 65 72 } //01 00  klogger
		$a_01_2 = {6d 61 69 6e 2e 6b 65 79 4c 6f 67 67 65 72 } //01 00  main.keyLogger
		$a_01_3 = {6d 61 69 6e 2e 77 69 6e 64 6f 77 4c 6f 67 67 65 72 } //01 00  main.windowLogger
		$a_01_4 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6b 62 69 6e 61 6e 69 2f 73 63 72 65 65 6e 73 68 6f 74 2e 69 6e 69 74 } //01 00  github.com/kbinani/screenshot.init
		$a_01_5 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6b 62 69 6e 61 6e 69 2f 73 63 72 65 65 6e 73 68 6f 74 2e 43 61 70 74 75 72 65 44 69 73 70 6c 61 79 } //01 00  github.com/kbinani/screenshot.CaptureDisplay
		$a_01_6 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6b 62 69 6e 61 6e 69 2f 73 63 72 65 65 6e 73 68 6f 74 2e 67 65 74 44 65 73 6b 74 6f 70 57 69 6e 64 6f 77 } //01 00  github.com/kbinani/screenshot.getDesktopWindow
		$a_01_7 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6b 62 69 6e 61 6e 69 2f 73 63 72 65 65 6e 73 68 6f 74 2e 47 65 74 44 69 73 70 6c 61 79 42 6f 75 6e 64 73 } //00 00  github.com/kbinani/screenshot.GetDisplayBounds
	condition:
		any of ($a_*)
 
}