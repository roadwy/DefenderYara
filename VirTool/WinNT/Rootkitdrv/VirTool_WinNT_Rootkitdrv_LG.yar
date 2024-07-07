
rule VirTool_WinNT_Rootkitdrv_LG{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.LG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 } //1 \Registry\Machine\System\CurrentControlSet\Services
		$a_03_1 = {53 53 53 53 50 68 00 00 00 40 ff b5 90 01 02 ff ff ff 15 90 01 04 eb 12 50 68 00 00 00 82 ff b5 90 01 02 ff ff ff 15 90 01 04 5e 5b 90 00 } //1
		$a_03_2 = {ff 75 1c 8d 45 90 01 01 ff 75 18 ff 75 14 6a 00 50 ff 75 0c ff 15 90 01 04 ff 75 0c 8b f0 ff 15 90 01 04 8b c6 5e c9 c2 18 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}