
rule VirTool_WinNT_Rootkitdrv_LD{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 4e 41 4d 45 5f 54 4f 5d 00 5b 4d 41 49 4c 5f 54 4f 5d 00 5b 54 48 45 42 41 54 5f 4d 45 53 53 49 44 5d 00 5b 4f 55 54 4c 4f 4f 4b 5f 4d 45 53 53 49 44 5d } //1 乛䵁彅佔]䵛䥁彌佔]呛䕈䅂彔䕍卓䑉]佛呕佌䭏䵟卅䥓嵄
		$a_03_1 = {c6 00 e9 8b ?? 2b ?? 89 ?? 01 8b 45 0c 2b [0-04] 83 e8 05 89 ?? 01 c6 ?? e9 } //1
		$a_03_2 = {80 f9 40 75 06 81 cb 00 01 00 00 80 f9 80 75 ?? 0b df eb ?? 80 f9 40 75 06 81 cb 00 01 00 00 80 f9 80 75 06 81 cb 00 04 00 00 3c 04 75 ?? 8a 06 24 07 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}