
rule VirTool_Win32_CeeInject_gen_LF{
	meta:
		description = "VirTool:Win32/CeeInject.gen!LF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f be 8c 05 dc fd ff ff 8b 85 70 fd ff ff 99 f7 7d f4 8b 45 10 0f be 14 10 33 ca 8b 85 74 fd ff ff 88 8c 05 dc fd ff ff 8b 8d 70 fd ff ff 83 c1 01 89 8d 70 fd ff ff 8b 85 74 fd ff ff 99 f7 7d f4 85 d2 75 } //1
		$a_01_1 = {0f be 08 8b 85 70 fd ff ff 99 f7 bd 88 fd ff ff 8b 45 20 0f be 14 10 33 ca 8b 45 f0 03 85 10 fc ff ff 88 08 } //1
		$a_03_2 = {8b f4 8b 95 a8 fb ff ff 52 8b 85 f4 fb ff ff 50 ff 95 44 fb ff ff 3b f4 e8 ?? ?? ?? ?? c7 85 40 fb ff ff f7 2d 00 00 8d 8d 40 fb ff ff 89 8d 3c fb ff ff c7 85 38 fb ff ff 00 00 00 00 c7 85 34 fb ff ff 1c 02 00 00 c7 85 34 fb ff ff 8d 07 00 00 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}