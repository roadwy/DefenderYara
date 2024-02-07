
rule Trojan_Win32_WebToos_D{
	meta:
		description = "Trojan:Win32/WebToos.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 65 62 54 6f 6f 73 00 } //01 00  敗呢潯s
		$a_01_1 = {44 49 53 50 49 44 5f 4e 45 57 57 49 4e 44 4f 57 32 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 3e 0a } //01 00 
		$a_01_2 = {00 74 61 73 6b 5f 6c 69 73 74 00 00 00 6c 69 6e 6b 5f 6c 69 73 74 00 } //01 00 
		$a_01_3 = {58 57 65 62 42 72 6f 77 73 65 72 00 } //01 00  坘扥牂睯敳r
		$a_01_4 = {49 45 63 74 72 6c 2e 6c 6f 67 } //00 00  IEctrl.log
	condition:
		any of ($a_*)
 
}