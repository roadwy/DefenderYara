
rule Trojan_BAT_ProfileStylez_A{
	meta:
		description = "Trojan:BAT/ProfileStylez.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 20 af 00 0a 00 6f ?? 00 00 0a 13 (04|05) (|) 08 09 72 } //1
		$a_01_1 = {42 48 4f 5f 48 65 6c 6c 6f 57 6f 72 6c 64 2e 49 4f 62 6a 65 63 74 57 69 74 68 53 69 74 65 2e 47 65 74 53 69 74 65 } //1 BHO_HelloWorld.IObjectWithSite.GetSite
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_ProfileStylez_A_2{
	meta:
		description = "Trojan:BAT/ProfileStylez.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 4f 20 55 53 45 20 54 48 45 70 72 6f 66 69 6c 65 } //1 TO USE THEprofile
		$a_01_1 = {65 78 74 65 6e 73 69 6f 6e 5f 32 5f 35 5f 31 2e 63 72 78 } //1 extension_2_5_1.crx
		$a_01_2 = {61 6c 6c 6f 77 20 75 73 20 74 6f 20 64 69 73 70 6c 61 79 20 70 6f 70 2d 75 70 2c 20 70 6f 70 2d 75 6e 64 65 72 20 61 6e 64 20 6f 74 68 65 72 20 74 79 70 65 73 20 6f 66 20 61 64 76 65 72 74 69 73 65 6d 65 6e 74 73 } //1 allow us to display pop-up, pop-under and other types of advertisements
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}