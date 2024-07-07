
rule VirTool_WinNT_Rootkitdrv_gen_FU{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.gen!FU,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 78 0c 00 a0 22 00 75 20 83 78 08 04 75 10 8b 46 0c 85 c0 74 09 8b 00 a3 08 09 01 00 eb 11 b8 06 02 00 c0 89 46 18 eb } //10
		$a_01_1 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 53 00 53 00 44 00 54 00 48 00 4f 00 4f 00 4b 00 } //1 \DosDevices\SSDTHOOK
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}