
rule Virus_Win64_Expiro_AEX_MTB{
	meta:
		description = "Virus:Win64/Expiro.AEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 5c 24 58 48 89 44 24 50 48 89 5c 24 48 48 89 5c 24 40 89 5c 24 38 89 5c 24 30 41 b9 00 00 cf 00 4c 8b c7 48 8b d7 33 c9 89 5c 24 28 89 5c 24 20 ff 15 7d 10 01 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}