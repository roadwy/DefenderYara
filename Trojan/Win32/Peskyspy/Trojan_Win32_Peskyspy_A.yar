
rule Trojan_Win32_Peskyspy_A{
	meta:
		description = "Trojan:Win32/Peskyspy.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 74 65 73 74 2f 69 6e 70 75 74 5f 6e 67 2e 70 68 70 } //1 /test/input_ng.php
		$a_01_1 = {5f 43 4f 4e 46 49 47 5f 53 49 4c 45 4e 54 5f 4d 4f 44 45 5f } //1 _CONFIG_SILENT_MODE_
		$a_01_2 = {5f 43 4f 4e 46 49 47 5f 55 50 4c 4f 41 44 5f } //1 _CONFIG_UPLOAD_
		$a_01_3 = {44 65 6c 65 74 65 20 56 6f 49 50 2d 52 65 63 6f 72 64 65 72 } //1 Delete VoIP-Recorder
		$a_01_4 = {6c 6f 6f 6b 75 70 2e 6f 75 74 } //1 lookup.out
		$a_01_5 = {73 6b 79 70 65 2e 65 78 65 } //1 skype.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}