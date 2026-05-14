
rule Trojan_Win64_Vidar_AHE_MTB{
	meta:
		description = "Trojan:Win64/Vidar.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 cb 48 c1 f9 ?? 48 c1 e1 ?? 48 89 de 48 29 cb 66 0f 1f 44 00 00 48 83 fb ?? 72 } //20
		$a_01_1 = {48 c7 84 24 30 01 00 00 91 00 00 00 48 c7 84 24 38 01 00 00 16 01 00 00 48 c7 84 24 40 01 00 00 88 01 00 00 48 c7 84 24 48 01 00 00 c3 01 00 00 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*30) >=50
 
}