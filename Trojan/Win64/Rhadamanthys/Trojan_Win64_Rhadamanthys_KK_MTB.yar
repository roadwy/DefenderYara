
rule Trojan_Win64_Rhadamanthys_KK_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c9 ff d6 [0-05] 4d 8d 00 4d 8d 00 83 eb 01 75 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}