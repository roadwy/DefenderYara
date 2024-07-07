
rule Trojan_BAT_Tedy_EM_MTB{
	meta:
		description = "Trojan:BAT/Tedy.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0c 1a 11 0c 1a 95 11 0d 1a 95 5a 9e 11 0c 1b 11 0c 1b 95 11 0d 1b 95 58 9e 11 17 } //4
		$a_01_1 = {57 00 69 00 6e 00 4d 00 65 00 64 00 69 00 61 00 } //1 WinMedia
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}