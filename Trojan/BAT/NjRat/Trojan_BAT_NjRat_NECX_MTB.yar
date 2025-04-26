
rule Trojan_BAT_NjRat_NECX_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 17 9a 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a } //10
		$a_01_1 = {57 4f 4c 46 44 45 43 52 59 50 54 } //2 WOLFDECRYPT
		$a_01_2 = {4e 6f 49 73 47 6f 6f 64 } //2 NoIsGood
		$a_01_3 = {46 75 63 6b 59 6f 75 } //2 FuckYou
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}