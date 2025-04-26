
rule VirTool_WinNT_Sinowal_E{
	meta:
		description = "VirTool:WinNT/Sinowal.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 01 45 fc 8b 06 8b 7d f4 9c [0-0b] 83 cf 00 3b fe 5f 74 } //1
		$a_01_1 = {b8 aa aa aa aa 8d 7d f0 ab 56 ff 75 fc ab } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}