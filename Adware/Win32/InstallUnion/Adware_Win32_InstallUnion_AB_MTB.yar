
rule Adware_Win32_InstallUnion_AB_MTB{
	meta:
		description = "Adware:Win32/InstallUnion.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {53 6f 66 74 77 61 72 65 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 45 78 74 65 6e 73 69 6f 6e 73 5c 67 6e 70 6c 68 61 68 62 63 6f 6c 64 62 69 6c 64 66 66 64 63 68 6e 65 61 65 70 61 70 63 63 62 6e } //Software\Google\Chrome\Extensions\gnplhahbcoldbildffdchneaepapccbn  01 00 
		$a_80_1 = {47 65 6e 65 72 69 63 53 65 74 75 70 2e 65 78 65 } //GenericSetup.exe  01 00 
		$a_80_2 = {69 6e 73 74 61 6c 6c 4f 66 66 65 72 } //installOffer  01 00 
		$a_80_3 = {21 6e 62 73 70 5f 69 6e 6a 65 63 74 69 6f 6e } //!nbsp_injection  01 00 
		$a_80_4 = {2f 63 61 6c 6c 62 61 63 6b 2f 67 65 6f 2f 67 65 6f 2e 70 68 70 } ///callback/geo/geo.php  00 00 
	condition:
		any of ($a_*)
 
}