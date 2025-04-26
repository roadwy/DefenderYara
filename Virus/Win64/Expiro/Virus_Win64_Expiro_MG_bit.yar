
rule Virus_Win64_Expiro_MG_bit{
	meta:
		description = "Virus:Win64/Expiro.MG!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 8b 73 60 4b 8b 36 81 e6 df 00 df 00 4d 8b 76 0b 43 01 f6 47 c1 e6 02 } //1
		$a_03_1 = {8b 30 81 f6 ?? ?? ?? ?? 43 89 33 4f 83 c3 04 48 ff c0 45 83 ee 04 4a ff c0 4e ff c0 4c ff c0 47 85 f6 75 dc } //1
		$a_01_2 = {55 48 89 e5 48 83 ec 30 4c 89 45 20 48 89 55 18 48 89 4d 10 49 c7 c3 06 00 00 00 48 c7 c0 48 00 00 00 48 99 49 f7 fb 48 89 45 e0 4d 89 da 49 83 ea 03 4c 89 55 f8 4c 8b 5d f8 49 83 c3 0a 4c 89 5d f0 49 83 eb 08 4c 89 5d e8 48 c7 c0 28 00 00 00 4c 8b 55 e8 48 99 49 f7 fa 48 89 45 d8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}