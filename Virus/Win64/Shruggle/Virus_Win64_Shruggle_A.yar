
rule Virus_Win64_Shruggle_A{
	meta:
		description = "Virus:Win64/Shruggle.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 68 72 75 67 20 2d 20 72 6f 79 20 67 20 62 69 76 48 [0-90] 6b ?? 65 ?? 72 ?? 6e ?? 65 ?? 6c ?? 33 ?? 32 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}