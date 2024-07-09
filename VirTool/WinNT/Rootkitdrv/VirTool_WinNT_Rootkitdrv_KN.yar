
rule VirTool_WinNT_Rootkitdrv_KN{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KN,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 db 8b 0d ?? ?? ?? ?? 8b 09 8b 14 9d ?? ?? ?? ?? 39 14 99 74 06 8d 0c 99 f0 87 11 43 3b 1d ?? ?? ?? ?? 7c dd a1 ?? ?? ?? ?? 0b c0 74 0f 80 38 e9 75 0a c6 00 2b c7 40 01 e1 c1 e9 02 0f 20 c0 0d 00 00 01 00 0f 22 c0 61 b8 82 01 00 c0 c9 c2 08 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}