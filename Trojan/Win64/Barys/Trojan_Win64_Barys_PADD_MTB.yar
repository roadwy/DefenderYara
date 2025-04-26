
rule Trojan_Win64_Barys_PADD_MTB{
	meta:
		description = "Trojan:Win64/Barys.PADD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 b8 34 77 34 77 34 77 34 77 45 0f b7 c2 48 8b c8 42 8b 14 83 49 03 d7 0f b6 02 85 c0 0f 84 88 } //1
		$a_01_1 = {48 65 6c 6c 73 47 61 74 65 2e 70 64 62 } //1 HellsGate.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}