
rule VirTool_WinNT_Rootkitdrv_LA{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 87 ?? ?? ?? ?? 33 c9 8a 0d ?? ?? ?? ?? 33 c1 8b 4d ?? 88 04 0f 47 eb } //1
		$a_03_1 = {53 8a 1c 11 32 1d ?? ?? ?? ?? 88 1a 42 48 75 f1 5b } //1
		$a_03_2 = {6a 08 8d 45 ?? 50 6a 09 6a ff ff 15 ?? ?? ?? ?? f6 45 08 02 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}