
rule Trojan_BAT_Rhadamanthys_BN_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 00 06 1b 3a ?? 00 00 00 26 20 00 00 00 00 7e } //2
		$a_03_1 = {ff ff 26 20 00 00 00 00 38 ?? ff ff ff dd ?? 00 00 00 13 } //2
		$a_01_2 = {4c 00 72 00 65 00 6c 00 66 00 75 00 6e 00 6d 00 6d 00 78 00 62 00 75 00 71 00 69 00 66 00 7a 00 71 00 } //1 Lrelfunmmxbuqifzq
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}