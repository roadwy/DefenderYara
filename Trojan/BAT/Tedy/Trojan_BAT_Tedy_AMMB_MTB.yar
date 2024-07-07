
rule Trojan_BAT_Tedy_AMMB_MTB{
	meta:
		description = "Trojan:BAT/Tedy.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 11 0f 07 11 0f 91 08 61 d2 9c 11 0f 17 58 13 0f 11 0f 07 8e 69 32 e8 } //2
		$a_00_1 = {43 00 72 00 65 00 61 00 74 00 65 00 54 00 68 00 72 00 65 00 61 00 64 00 } //1 CreateThread
		$a_00_2 = {57 00 61 00 69 00 74 00 46 00 6f 00 72 00 53 00 69 00 6e 00 67 00 6c 00 65 00 4f 00 62 00 6a 00 65 00 63 00 74 00 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}