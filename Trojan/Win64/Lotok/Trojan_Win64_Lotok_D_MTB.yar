
rule Trojan_Win64_Lotok_D_MTB{
	meta:
		description = "Trojan:Win64/Lotok.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 48 81 ec a0 00 00 00 48 c7 c1 00 00 00 00 48 c7 c2 ?? ac 00 00 49 c7 c0 00 10 00 00 4c 8d 49 40 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}