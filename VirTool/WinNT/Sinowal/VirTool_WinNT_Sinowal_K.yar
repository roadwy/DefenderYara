
rule VirTool_WinNT_Sinowal_K{
	meta:
		description = "VirTool:WinNT/Sinowal.K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 3d 00 05 df ff 21 a1 00 ee 75 12 } //1
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 44 00 69 00 73 00 6b 00 25 00 69 00 } //1 \Device\HardDisk%i
		$a_01_2 = {81 38 30 00 68 69 75 02 eb 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}