
rule VirTool_Win32_HookGina_B{
	meta:
		description = "VirTool:Win32/HookGina.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b ec 00 e9 00 00 00 00 00 90 09 03 00 8b ff 55 } //1
		$a_01_1 = {55 00 73 00 65 00 72 00 20 00 20 00 20 00 20 00 3d 00 20 00 25 00 73 00 20 00 0d 00 0a 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 20 00 20 00 3d 00 20 00 25 00 73 00 20 00 0d 00 0a 00 50 00 61 00 73 00 73 00 20 00 20 00 20 00 20 00 3d 00 20 00 25 00 73 00 20 00 0d 00 0a 00 4f 00 6c 00 64 00 50 00 61 00 73 00 73 00 20 00 3d 00 20 00 25 00 73 00 } //1
		$a_01_2 = {25 64 2f 25 64 2f 25 64 2f 25 64 3a 25 64 3a 25 64 00 57 6c 78 4c 6f 67 67 65 64 4f 75 74 53 41 53 00 6d 73 67 69 6e 61 2e 64 6c 6c } //1 搥┯⽤搥┯㩤搥┺d汗䱸杯敧佤瑵䅓S獭楧慮搮汬
		$a_03_3 = {8d 44 24 04 50 6a 40 6a 05 51 c7 44 24 14 00 00 00 00 ff d6 0f b6 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 10 0f b6 0d ?? ?? ?? ?? 88 48 01 0f b6 15 ?? ?? ?? ?? 88 50 02 0f b6 0d ?? ?? ?? ?? 88 48 03 0f b6 15 ?? ?? ?? ?? 88 50 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}