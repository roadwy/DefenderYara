
rule Trojan_Win64_Donut_C_MTB{
	meta:
		description = "Trojan:Win64/Donut.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 20 65 48 8b 04 25 30 00 00 00 49 8b f8 48 8b f2 48 8b e9 45 33 d2 4c 8b 48 60 49 8b 41 } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}