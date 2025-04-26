
rule TrojanSpy_MacOS_Keylogger_B_MTB{
	meta:
		description = "TrojanSpy:MacOS/Keylogger.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 77 69 66 74 53 70 79 } //1 SwiftSpy
		$a_01_1 = {43 6c 69 70 62 6f 61 72 64 4d 6f 6e 69 74 6f 72 } //1 ClipboardMonitor
		$a_01_2 = {2d 61 6c 6c 6b 65 79 73 } //1 -allkeys
		$a_01_3 = {2f 6d 61 69 6e 2e 73 77 69 66 74 } //1 /main.swift
		$a_01_4 = {2d 6b 65 79 6c 6f 67 } //1 -keylog
		$a_01_5 = {2d 73 63 72 65 65 6e 73 68 6f 74 20 2f 74 6d 70 } //1 -screenshot /tmp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}