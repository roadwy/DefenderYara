
rule VirTool_WinNT_Rootkitdrv_OM_bit{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.OM!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 f8 48 75 7a 48 8b 44 24 28 0f b6 40 01 3d 8d 00 00 00 75 6a 48 8b 44 24 28 0f b6 40 02 83 f8 0d 75 5c 48 8b 44 24 28 0f b6 40 07 83 f8 48 75 4e 48 8b 44 24 28 0f b6 40 08 3d 8b 00 00 00 75 3e 48 8b 44 24 28 0f b6 40 09 3d d7 00 00 00 } //01 00 
		$a_01_1 = {6d 73 76 63 64 6c 78 33 32 2e 64 61 74 } //01 00  msvcdlx32.dat
		$a_01_2 = {62 63 74 6c 69 73 74 2e 64 61 74 } //01 00  bctlist.dat
		$a_01_3 = {66 6b 5f 64 72 76 2e 70 64 62 } //00 00  fk_drv.pdb
	condition:
		any of ($a_*)
 
}