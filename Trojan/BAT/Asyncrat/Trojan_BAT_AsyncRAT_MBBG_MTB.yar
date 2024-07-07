
rule Trojan_BAT_AsyncRAT_MBBG_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 02 8e b7 17 da 13 10 13 0f 2b 30 11 0c 11 0f 02 11 0f 91 11 06 61 11 09 11 08 91 61 b4 9c 11 08 03 } //1
		$a_01_1 = {68 00 4d 00 5a 00 59 00 6f 00 72 00 75 00 6d 00 4d 00 61 00 54 00 45 00 6c 00 6e 00 49 00 } //1 hMZYorumMaTElnI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}