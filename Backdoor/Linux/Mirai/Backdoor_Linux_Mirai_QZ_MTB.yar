
rule Backdoor_Linux_Mirai_QZ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.QZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {d8 f6 12 0f cf ff 08 72 fc 13 03 b0 40 a3 e0 78 e0 78 fc 13 02 b0 44 6a fc 1b 80 b0 e0 78 e0 78 f8 13 02 b0 42 22 02 01 f8 1b 80 b0 30 f0 e0 78 e0 78 } //1
		$a_00_1 = {09 f4 ec 13 02 b0 40 82 61 6a ec 13 02 b0 60 a2 e0 78 } //1
		$a_00_2 = {e0 78 fc 13 02 b0 41 6a fc 1b 80 b0 e0 78 e0 78 f8 13 02 b0 61 6a f8 1b c0 b0 e0 78 e0 78 40 8a 4b 7a f0 f5 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}