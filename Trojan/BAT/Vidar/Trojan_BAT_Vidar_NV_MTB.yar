
rule Trojan_BAT_Vidar_NV_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {1f 10 63 20 90 01 03 00 5f d2 6f 90 01 03 0a 19 13 0b 38 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {41 6e 79 44 65 73 6b 20 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //01 00  AnyDesk Installer.exe
		$a_01_2 = {4e 70 6e 61 64 46 42 61 61 78 6f 6d } //00 00  NpnadFBaaxom
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Vidar_NV_MTB_2{
	meta:
		description = "Trojan:BAT/Vidar.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {d0 8f 02 00 04 28 90 01 02 00 0a 6f 90 01 02 00 0a 07 1f 10 8d 90 01 02 00 01 25 d0 90 01 02 00 04 28 90 01 02 00 0a 6f 90 01 02 00 0a 06 07 6f 90 01 02 00 0a 17 73 90 01 02 00 0a 0c 08 02 16 02 8e 69 6f 90 01 02 00 0a 90 00 } //01 00 
		$a_01_1 = {69 6e 67 65 6e 69 6f 75 73 5f 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 5f 73 6f 6c 75 74 69 6f 6e } //00 00  ingenious_installation_solution
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Vidar_NV_MTB_3{
	meta:
		description = "Trojan:BAT/Vidar.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 0c 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 17 8d 90 01 01 00 00 01 0d 09 16 17 8d 90 01 01 00 00 01 25 13 04 11 04 16 7f 90 01 01 00 00 04 d3 16 58 47 69 20 90 01 01 00 00 00 61 9d 73 90 01 01 00 00 0a a2 09 16 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {75 72 63 68 69 6e 73 53 61 70 66 75 6c } //01 00  urchinsSapful
		$a_01_2 = {73 61 70 66 75 6c 57 69 73 70 } //00 00  sapfulWisp
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Vidar_NV_MTB_4{
	meta:
		description = "Trojan:BAT/Vidar.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {7e 01 00 00 04 06 7e 90 01 03 04 8e 69 6a 5d d4 91 7e 90 01 03 04 06 7e 90 01 03 04 8e 69 6a 5d d4 91 61 28 90 01 03 0a 7e 90 01 03 04 06 17 6a 58 7e 90 01 03 04 8e 69 6a 5d d4 91 28 90 01 03 0a 59 20 90 01 03 00 58 20 90 01 03 00 5d 28 90 01 03 0a 9c 00 06 17 6a 58 0a 06 7e 90 01 03 04 8e 69 17 59 1c 5a 6a fe 02 16 fe 01 0b 07 3a 90 01 03 ff 90 00 } //01 00 
		$a_01_1 = {3a 00 2f 00 2f 00 67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 70 00 61 00 72 00 74 00 61 00 31 00 33 00 37 00 2f 00 63 00 72 00 79 00 70 00 74 00 73 00 2f 00 72 00 61 00 77 00 2f 00 6d 00 61 00 69 00 6e 00 2f 00 45 00 33 00 32 00 } //01 00  ://github.com/sparta137/crypts/raw/main/E32
		$a_01_2 = {49 61 6e 2e 46 72 6d 4d 61 7a 65 2e 72 65 73 6f 75 72 63 65 73 } //00 00  Ian.FrmMaze.resources
	condition:
		any of ($a_*)
 
}