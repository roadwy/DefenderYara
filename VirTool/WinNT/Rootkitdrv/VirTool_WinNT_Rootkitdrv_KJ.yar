
rule VirTool_WinNT_Rootkitdrv_KJ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 5d fc 2b c1 8b 0a 03 c7 3b 04 99 8d 0c 99 74 02 89 01 } //1
		$a_03_1 = {8b 45 fc 8b 4d fc c1 e0 09 c1 e1 02 8d 80 90 01 04 89 84 0d 90 01 02 ff ff 05 90 01 04 89 84 0d 90 01 02 ff ff 05 90 01 04 ff 45 fc 90 00 } //1
		$a_03_2 = {8b 7d 08 05 90 01 04 89 45 90 01 01 83 65 90 01 01 00 8b 47 3c 8b 74 38 78 8b 44 3e 20 03 f7 03 c7 8b 5e 1c 8b 4e 24 03 df 03 cf 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}