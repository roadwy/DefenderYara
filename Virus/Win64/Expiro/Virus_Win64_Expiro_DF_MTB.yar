
rule Virus_Win64_Expiro_DF_MTB{
	meta:
		description = "Virus:Win64/Expiro.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 8b 48 60 48 8b 31 81 e6 df 00 df 00 48 8b 49 0b 03 ce c1 e9 02 81 e9 d2 4c 91 0c 4e 83 f9 00 74 } //1
		$a_01_1 = {49 8b 5c 24 60 4c 8b 1b 45 81 e3 df 00 df 00 48 8b 5b 0b 46 01 db c1 eb 02 81 eb d2 4c 91 0c 4c 83 fb 00 74 09 49 8b 1c 24 } //1
		$a_01_2 = {4f 8b 75 60 4b 8b 06 81 e0 df 00 df 00 4d 8b 76 0c 43 c1 e6 08 41 01 c6 41 c1 e6 01 43 81 ee 96 66 8a 64 49 83 fe 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}