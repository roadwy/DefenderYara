
rule HackTool_Linux_DiscoverPrivateSSHkeys_B{
	meta:
		description = "HackTool:Linux/DiscoverPrivateSSHkeys.B,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {66 00 69 00 6e 00 64 00 20 00 2f 00 20 00 2d 00 6e 00 61 00 6d 00 65 00 20 00 69 00 64 00 5f 00 64 00 73 00 61 00 } //01 00  find / -name id_dsa
		$a_01_1 = {2d 00 65 00 78 00 65 00 63 00 20 00 63 00 70 00 20 00 2d 00 2d 00 70 00 61 00 72 00 65 00 6e 00 74 00 73 00 20 00 7b 00 7d 00 } //01 00  -exec cp --parents {}
		$a_01_2 = {2d 00 65 00 78 00 65 00 63 00 20 00 72 00 73 00 79 00 6e 00 63 00 20 00 2d 00 52 00 20 00 7b 00 7d 00 } //00 00  -exec rsync -R {}
	condition:
		any of ($a_*)
 
}