
rule Virus_Win32_Viking_AVK_MTB{
	meta:
		description = "Virus:Win32/Viking.AVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 8d 95 60 fd ff ff 33 c0 e8 a0 a7 ff ff 8b 95 60 fd ff ff 8d 45 ec 59 e8 c9 b3 ff ff 8b 45 ec e8 75 b5 ff ff 50 e8 e3 c2 ff ff } //5
		$a_03_1 = {68 b4 83 40 00 8d 95 44 fd ff ff 33 c0 e8 ?? ?? ?? ?? ff b5 44 fd ff ff 68 cc 83 40 00 68 d8 83 40 00 8d 95 40 fd ff ff 33 c0 e8 ?? ?? ?? ?? ff b5 40 fd ff ff 68 ec 83 40 00 68 f8 83 40 00 68 10 84 40 00 ff 75 ec 68 20 84 40 00 8d 95 38 fd ff ff 33 c0 } //3
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*3) >=8
 
}