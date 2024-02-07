
rule VirTool_WinNT_Hackdef_gen_G{
	meta:
		description = "VirTool:WinNT/Hackdef.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 a1 08 0c 01 00 8b 08 89 4d 90 01 01 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 90 01 02 0d 01 00 a1 24 0c 01 00 8b 48 01 8b 45 fc 8d 0c 88 87 11 89 90 01 02 0d 01 00 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 33 c0 8b e5 5d c3 90 00 } //01 00 
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 62 00 63 00 6f 00 6e 00 75 00 73 00 62 00 } //01 00  \Device\bconusb
		$a_00_2 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 62 00 63 00 6f 00 6e 00 75 00 73 00 62 00 } //00 00  \DosDevices\bconusb
	condition:
		any of ($a_*)
 
}