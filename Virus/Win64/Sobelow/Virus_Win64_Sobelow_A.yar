
rule Virus_Win64_Sobelow_A{
	meta:
		description = "Virus:Win64/Sobelow.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 65 ff 34 25 80 14 00 00 53 56 57 41 50 41 51 c8 98 02 00 6a 00 e8 4e 00 00 00 68 d3 96 11 fa d9 a0 4b 64 1e 17 22 2e 7c ea a8 a8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}