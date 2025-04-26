
rule VirTool_Win32_CeeInject_CF{
	meta:
		description = "VirTool:Win32/CeeInject.CF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {eb 3b 8b 45 f0 33 d2 f7 75 f4 0f af 45 fc 89 45 a8 83 65 ac 00 df 6d a8 dd 1d } //1
		$a_01_1 = {8b 45 0c 48 48 0f 84 c9 00 00 00 83 e8 0d 74 75 2d 02 01 00 00 74 30 e8 } //1
		$a_03_2 = {01 01 20 a1 07 00 0f 82 ?? fc ff ff 8b 45 ec c9 c3 } //1
		$a_01_3 = {7e 1c 81 bc 82 6c 2b 00 00 b0 21 40 00 0f } //1
		$a_01_4 = {61 73 74 72 6f 20 25 30 34 78 2d 2d 25 30 34 78 20 70 65 72 20 70 69 78 65 6c 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}