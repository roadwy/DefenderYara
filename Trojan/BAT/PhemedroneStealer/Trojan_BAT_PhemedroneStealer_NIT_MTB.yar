
rule Trojan_BAT_PhemedroneStealer_NIT_MTB{
	meta:
		description = "Trojan:BAT/PhemedroneStealer.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 65 63 6b 6f 42 72 6f 77 73 65 72 73 4c 69 73 74 } //2 GeckoBrowsersList
		$a_01_1 = {47 65 74 4d 6f 7a 69 6c 6c 61 42 72 6f 77 73 65 72 73 } //2 GetMozillaBrowsers
		$a_01_2 = {50 72 6f 67 72 61 6d 46 69 6c 65 73 43 68 69 6c 64 72 65 6e } //2 ProgramFilesChildren
		$a_01_3 = {47 65 74 4d 6f 7a 69 6c 6c 61 50 61 74 68 } //2 GetMozillaPath
		$a_01_4 = {73 65 74 5f 73 55 72 6c } //1 set_sUrl
		$a_00_5 = {76 00 6d 00 77 00 61 00 72 00 65 00 } //1 vmware
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=9
 
}