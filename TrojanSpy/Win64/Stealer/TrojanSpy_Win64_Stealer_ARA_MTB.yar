
rule TrojanSpy_Win64_Stealer_ARA_MTB{
	meta:
		description = "TrojanSpy:Win64/Stealer.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c8 4d 8b c2 80 e1 07 c0 e1 03 49 d3 e8 46 30 04 08 48 ff c0 48 83 f8 33 72 e4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}