
rule VirTool_Win32_VBInject_gen_BF{
	meta:
		description = "VirTool:Win32/VBInject.gen!BF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c4 18 81 bd ?? ?? ff ff 50 45 00 00 74 0c 83 8d ?? ?? ff ff ff e9 } //1
		$a_03_1 = {8a 18 32 1d ?? ?? ?? ?? ff 37 e8 ?? ?? ff ff 88 18 a1 ?? ?? ?? ?? 83 c0 01 70 15 3b 45 0c a3 ?? ?? ?? ?? 0f 8e } //1
		$a_03_2 = {fe ff ff 83 c4 14 03 85 90 90 fd ff ff ba ?? ?? ?? ?? 8d 8d fc fc ff ff 0f 80 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}