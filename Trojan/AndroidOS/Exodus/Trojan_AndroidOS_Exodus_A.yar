
rule Trojan_AndroidOS_Exodus_A{
	meta:
		description = "Trojan:AndroidOS/Exodus.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {6f 6e 50 72 69 76 61 74 65 53 65 72 76 69 63 65 53 74 61 72 74 43 6f 6d 6d 61 6e 64 } //01 00  onPrivateServiceStartCommand
		$a_00_1 = {73 65 74 53 74 61 67 69 6e 67 48 6f 73 74 } //01 00  setStagingHost
		$a_00_2 = {61 64 31 2e 66 62 73 62 61 2e 63 6f 6d } //01 00  ad1.fbsba.com
		$a_00_3 = {4c 67 34 50 56 58 31 65 51 56 39 72 64 53 6b 4f 43 42 78 35 58 45 52 59 61 33 39 39 43 51 6b 63 66 51 68 49 44 48 46 33 66 31 30 4a 43 58 70 5a } //01 00  Lg4PVX1eQV9rdSkOCBx5XERYa399CQkcfQhIDHF3f10JCXpZ
		$a_00_4 = {65 64 64 64 30 33 31 37 2d 32 62 64 63 2d 34 31 34 30 2d 38 36 63 62 2d 30 65 38 64 37 30 34 37 62 38 37 34 } //00 00  eddd0317-2bdc-4140-86cb-0e8d7047b874
		$a_00_5 = {5d 04 00 } //00 cd 
	condition:
		any of ($a_*)
 
}