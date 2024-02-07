
rule VirTool_Win32_Obfuscator_RG{
	meta:
		description = "VirTool:Win32/Obfuscator.RG,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 45 d0 bc 0a 00 00 8d 45 e8 50 8d 45 d0 50 68 90 01 02 40 00 90 00 } //01 00 
		$a_02_1 = {8b 06 8d 4d ec 51 8d 4d d4 51 68 90 01 02 40 00 56 c7 45 d4 90 01 02 00 00 ff 50 30 90 00 } //0a 00 
		$a_00_2 = {5c 4a 4f 4b 45 52 2d 56 41 49 4f 5c } //00 00  \JOKER-VAIO\
	condition:
		any of ($a_*)
 
}