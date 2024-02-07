
rule HackTool_Win32_NetCatTool_LK_MTB{
	meta:
		description = "HackTool:Win32/NetCatTool.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 65 74 63 61 74 5c 52 65 6c 65 61 73 65 5c 6e 65 74 63 61 74 2e 70 64 62 } //01 00  netcat\Release\netcat.pdb
		$a_00_1 = {64 65 74 61 63 68 20 66 72 6f 6d 20 63 6f 6e 73 6f 6c 65 } //01 00  detach from console
		$a_00_2 = {73 65 6e 74 20 25 64 2c 20 72 63 76 64 20 25 64 } //01 00  sent %d, rcvd %d
		$a_00_3 = {6e 63 20 5b 2d 6f 70 74 69 6f 6e 73 5d 20 68 6f 73 74 6e 61 6d 65 20 70 6f 72 74 5b 73 5d 20 5b 70 6f 72 74 73 5d } //01 00  nc [-options] hostname port[s] [ports]
		$a_00_4 = {69 6e 62 6f 75 6e 64 20 70 72 6f 67 72 61 6d 20 74 6f 20 65 78 65 63 20 5b 64 61 6e 67 65 72 6f 75 73 21 21 5d } //00 00  inbound program to exec [dangerous!!]
	condition:
		any of ($a_*)
 
}