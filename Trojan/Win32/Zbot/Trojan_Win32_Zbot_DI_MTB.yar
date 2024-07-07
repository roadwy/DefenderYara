
rule Trojan_Win32_Zbot_DI_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 75 ac 81 f6 41 08 8b 24 0f b6 0e 46 46 81 f6 41 08 8b 24 89 75 ac b8 10 00 00 00 c1 c0 03 3b c8 0f 82 a9 07 00 00 2b c8 03 c9 8b 55 ec c1 c2 1b 03 d1 03 d1 c1 c2 05 89 55 ec 33 c0 3b c8 75 bf } //1
		$a_81_1 = {43 3a 5c 55 73 65 72 73 5c 61 64 6d 69 6e 5c 44 6f 77 6e 6c 6f 61 64 73 5c 77 65 66 75 6a 6e 2e 65 78 65 } //1 C:\Users\admin\Downloads\wefujn.exe
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}