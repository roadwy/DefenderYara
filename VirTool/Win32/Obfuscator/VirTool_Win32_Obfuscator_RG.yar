
rule VirTool_Win32_Obfuscator_RG{
	meta:
		description = "VirTool:Win32/Obfuscator.RG,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {c7 45 d0 bc 0a 00 00 8d 45 e8 50 8d 45 d0 50 68 ?? ?? 40 00 } //1
		$a_02_1 = {8b 06 8d 4d ec 51 8d 4d d4 51 68 ?? ?? 40 00 56 c7 45 d4 ?? ?? 00 00 ff 50 30 } //1
		$a_00_2 = {5c 4a 4f 4b 45 52 2d 56 41 49 4f 5c } //10 \JOKER-VAIO\
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*10) >=11
 
}