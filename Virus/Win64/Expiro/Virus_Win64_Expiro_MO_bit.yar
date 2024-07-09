
rule Virus_Win64_Expiro_MO_bit{
	meta:
		description = "Virus:Win64/Expiro.MO!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4b 60 4c 8b 29 43 81 e5 df 00 df 00 4a 8b 49 0c c1 e1 08 43 03 cd c1 e1 02 } //1
		$a_03_1 = {45 8b 2b 43 81 f5 ?? ?? ?? ?? 44 89 2b 49 ff c3 83 e9 04 4b ff c3 4f ff c3 4e 81 c3 04 00 00 00 4d ff c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}