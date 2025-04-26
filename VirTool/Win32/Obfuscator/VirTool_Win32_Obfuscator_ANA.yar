
rule VirTool_Win32_Obfuscator_ANA{
	meta:
		description = "VirTool:Win32/Obfuscator.ANA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 4b 61 74 65 72 69 6d 61 74 65 72 59 61 6d 65 6c 69 00 4e 6f 00 } //1 䬀瑡牥浩瑡牥慙敭楬一o
		$a_01_1 = {ff d0 e8 15 00 00 00 47 65 74 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 49 6e 66 6f 00 50 ff 15 } //1
		$a_03_2 = {83 7d 0c 01 0f 84 ?? ?? 00 00 83 7d 0c 02 0f 84 ?? ?? 00 00 81 7d 0c 13 01 00 00 0f 84 ?? ?? 00 00 83 7d 0c 05 0f 84 ?? ?? 00 00 81 7d 0c 95 05 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}