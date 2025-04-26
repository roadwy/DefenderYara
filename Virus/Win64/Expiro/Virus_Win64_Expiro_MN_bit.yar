
rule Virus_Win64_Expiro_MN_bit{
	meta:
		description = "Virus:Win64/Expiro.MN!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 78 60 4d 8b 1f 43 81 e3 df 00 df 00 4d 8b 7f 0c 43 c1 e7 08 47 01 } //1
		$a_03_1 = {44 8b 19 43 81 f3 ?? ?? ?? ?? 46 89 18 4f ff cf 4f ff cf 4a ff c1 4e ff c1 4c ff c1 4b ff cf 4d ff cf 48 ff c1 4e 83 c0 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}