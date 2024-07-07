
rule VirTool_Win64_Pringetesz_A_MTB{
	meta:
		description = "VirTool:Win64/Pringetesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {4c 89 a4 24 c8 02 00 00 90 01 07 4c 89 ac 24 c0 02 00 00 4c 89 b4 24 b8 02 00 00 4c 89 bc 24 b0 02 00 00 90 01 0c 48 8b cf 90 01 0d 48 8b cf 90 01 0d 48 8b cf 48 8b d8 90 01 0d 48 8b cf 4c 8b f0 90 00 } //1
		$a_03_1 = {48 8b f8 e8 90 01 04 8b d6 90 01 07 e8 90 01 09 ba ff ff 1f 00 90 01 0b 89 05 e9 42 00 00 85 c0 90 01 02 8b d0 90 00 } //1
		$a_03_2 = {48 8b 54 24 68 90 01 0c 48 8b 54 24 68 90 01 04 48 8b 4c 24 60 33 db 41 b9 cd 01 00 00 48 89 5c 24 20 90 01 03 89 05 4b 42 00 00 85 c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}