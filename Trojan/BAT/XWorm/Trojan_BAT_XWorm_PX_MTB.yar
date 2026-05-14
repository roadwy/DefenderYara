
rule Trojan_BAT_XWorm_PX_MTB{
	meta:
		description = "Trojan:BAT/XWorm.PX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_03_0 = {04 03 61 1f ?? 59 06 61 45 } //5
		$a_81_1 = {58 4c 6f 67 67 65 72 } //1 XLogger
		$a_81_2 = {63 61 6c 6c 6b } //1 callk
		$a_81_3 = {49 73 55 70 64 61 74 65 } //1 IsUpdate
		$a_81_4 = {41 63 74 69 76 61 74 65 50 6f 6e 67 } //1 ActivatePong
		$a_81_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //1 SetWindowsHookEx
		$a_81_6 = {4d 61 70 56 69 72 74 75 61 6c 4b 65 79 } //1 MapVirtualKey
		$a_81_7 = {49 4e 44 41 54 45 } //1 INDATE
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=12
 
}