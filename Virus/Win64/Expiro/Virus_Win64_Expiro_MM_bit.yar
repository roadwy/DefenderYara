
rule Virus_Win64_Expiro_MM_bit{
	meta:
		description = "Virus:Win64/Expiro.MM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 8b 61 60 4d 8b 1c 24 43 81 e3 df 00 df 00 4d 8b 64 24 0b 45 01 dc 45 c1 e4 02 } //1
		$a_03_1 = {46 8b 1f 43 81 f3 90 01 04 47 89 19 4e ff c7 4c ff c7 4e ff c7 41 83 ec 04 4d 81 c1 04 00 00 00 4e ff c7 47 85 e4 75 d7 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}