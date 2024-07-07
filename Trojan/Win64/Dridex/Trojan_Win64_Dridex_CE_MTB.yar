
rule Trojan_Win64_Dridex_CE_MTB{
	meta:
		description = "Trojan:Win64/Dridex.CE!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 68 31 c0 89 c1 48 8b 54 24 60 c7 44 24 5c 77 d0 cb 62 8b 44 24 5c 66 44 8b 44 24 5a 66 44 89 44 24 5a 48 81 c2 c3 12 4e 1f 41 89 c1 41 81 c1 89 2f 34 9d 48 89 54 24 60 41 89 c2 41 81 ca 27 04 40 54 44 89 54 24 54 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}