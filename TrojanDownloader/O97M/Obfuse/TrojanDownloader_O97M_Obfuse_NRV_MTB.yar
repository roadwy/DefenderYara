
rule TrojanDownloader_O97M_Obfuse_NRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 69 5f 6e 61 6d 65 } //01 00  Shell i_name
		$a_01_1 = {4e 6f 6e 63 65 20 3d 20 56 69 72 74 75 61 6c 4d 65 61 74 20 2b 20 22 20 22 20 2b 20 56 69 72 74 75 61 6c 4d 65 61 74 31 } //01 00  Nonce = VirtualMeat + " " + VirtualMeat1
		$a_01_2 = {6f 62 6a 31 2e 43 6c 61 73 73 31 6f 62 6a 0d 0a 0d 0a 45 6e 64 20 53 75 62 } //01 00 
		$a_01_3 = {61 73 73 61 73 2e 4e 65 77 58 0d 0a 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //01 00 
		$a_01_4 = {56 69 72 74 75 61 6c 4d 65 61 74 31 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 49 6d 61 67 65 31 2e 54 61 67 } //01 00  VirtualMeat1 = UserForm1.Image1.Tag
		$a_01_5 = {53 75 62 20 61 75 74 6f 5f 6f 70 65 6e 28 29 } //00 00  Sub auto_open()
	condition:
		any of ($a_*)
 
}