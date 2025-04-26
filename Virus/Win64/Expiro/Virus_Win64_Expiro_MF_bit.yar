
rule Virus_Win64_Expiro_MF_bit{
	meta:
		description = "Virus:Win64/Expiro.MF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {4d 8b 4f 60 4d 8b 19 43 81 e3 df 00 df 00 4f 8b 49 0b 47 01 d9 43 c1 e9 02 41 [0-06] 4d 85 c9 } //1
		$a_03_1 = {45 8b 5d 00 41 [0-06] 47 89 1f 4b ff c9 4d ff c5 } //1
		$a_01_2 = {55 48 89 e5 41 57 48 83 ec 48 48 c7 45 e8 0c 00 00 00 48 c7 c0 30 00 00 00 4c 8b 55 e8 48 99 49 f7 fa 49 89 c7 48 c7 c0 04 00 00 00 48 99 49 f7 ff 48 89 45 e0 4d 89 fb 49 83 eb 03 4c 89 5d d8 48 c7 45 d0 00 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}