
rule PWS_Win32_Zbot_gen_F{
	meta:
		description = "PWS:Win32/Zbot.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 64 61 74 61 00 } //-1 搮瑡a
		$a_00_1 = {00 2e 74 65 78 74 00 } //-2
		$a_00_2 = {2e 72 65 6c 6f 63 00 } //-1
		$a_00_3 = {2e 72 73 72 63 00 } //-1 爮牳c
		$a_03_4 = {55 8b ec 83 ec ?? 33 ?? 89 ?? 24 ?? ?? ?? ?? ?? ?? 33 ?? bf ?? ?? 41 00 89 7c 24 ?? 81 7c 24 ?? ?? ?? 00 00 75 06 8b 54 24 ?? 28 ?? ff 44 24 ?? c1 ?? 08 ?? 83 ?? 04 75 0a ?? ?? ?? ?? ?? ?? 00 00 00 00 bf ?? ?? 41 00 39 7c 24 ?? 72 ce ff 44 24 ?? 81 7c 24 ?? ?? ?? 00 00 76 b0 8b e5 5d } //2
	condition:
		((#a_00_0  & 1)*-1+(#a_00_1  & 1)*-2+(#a_00_2  & 1)*-1+(#a_00_3  & 1)*-1+(#a_03_4  & 1)*2) >=1
 
}