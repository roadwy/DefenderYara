
rule VirTool_WinNT_Piptim{
	meta:
		description = "VirTool:WinNT/Piptim,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 03 00 00 "
		
	strings :
		$a_00_0 = {90 90 33 c0 8b 00 c3 } //1
		$a_02_1 = {8b 42 01 8b 0d 10 40 01 00 8b 11 c7 04 82 ?? ?? 01 00 e8 ?? ?? ff ff fb c7 05 ?? 60 01 00 01 00 00 00 eb 43 83 7d 08 00 75 3d 83 3d ?? 60 01 00 01 75 34 fa a1 ?? 40 01 00 8b 48 01 8b 15 10 40 01 00 8b 02 8b 15 ?? 60 01 00 89 14 88 } //10
		$a_00_2 = {0f 20 c0 89 45 fc 25 ff ff fe ff 0f 22 c0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1) >=11
 
}