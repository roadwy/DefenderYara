
rule Trojan_BAT_XWorm_RR_MTB{
	meta:
		description = "Trojan:BAT/XWorm.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 57 6f 72 6d 43 6c 69 65 6e 74 } //1 XWormClient
		$a_01_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_XWorm_RR_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_1 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
		$a_01_2 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_01_3 = {43 6c 69 65 6e 74 53 6f 63 6b 65 74 } //1 ClientSocket
		$a_01_4 = {58 4c 6f 67 67 65 72 } //5 XLogger
		$a_01_5 = {58 57 6f 72 6d 43 6c 69 65 6e 74 26 26 } //5 XWormClient&&
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=14
 
}