
rule Trojan_BAT_Balamid_A{
	meta:
		description = "Trojan:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 77 69 6e 74 61 73 6b 31 36 2e 63 6f 6d 2f 75 72 6c 2e 74 78 74 } //www.wintask16.com/url.txt  1
		$a_80_1 = {75 73 65 72 5f 70 72 65 66 28 22 62 72 6f 77 73 65 72 2e 73 74 61 72 74 75 70 2e 68 6f 6d 65 70 61 67 65 22 } //user_pref("browser.startup.homepage"  1
		$a_80_2 = {22 73 74 61 72 74 75 70 5f 75 72 6c 73 22 } //"startup_urls"  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule Trojan_BAT_Balamid_A_2{
	meta:
		description = "Trojan:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 77 69 6e 74 61 73 6b 33 32 2e 63 6f 6d 2f 75 72 6c 2e 74 78 74 } //www.wintask32.com/url.txt  1
		$a_80_1 = {75 73 65 72 5f 70 72 65 66 28 22 62 72 6f 77 73 65 72 2e 73 74 61 72 74 75 70 2e 68 6f 6d 65 70 61 67 65 22 } //user_pref("browser.startup.homepage"  1
		$a_80_2 = {22 73 74 61 72 74 75 70 5f 75 72 6c 73 22 } //"startup_urls"  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule Trojan_BAT_Balamid_A_3{
	meta:
		description = "Trojan:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 77 69 6e 74 61 73 6b 36 34 2e 63 6f 6d 2f 75 72 6c 2e 74 78 74 } //www.wintask64.com/url.txt  1
		$a_80_1 = {75 73 65 72 5f 70 72 65 66 28 22 62 72 6f 77 73 65 72 2e 73 74 61 72 74 75 70 2e 68 6f 6d 65 70 61 67 65 22 } //user_pref("browser.startup.homepage"  1
		$a_80_2 = {22 75 72 6c 73 5f 74 6f 5f 72 65 73 74 6f 72 65 5f 6f 6e 5f 73 74 61 72 74 75 70 22 } //"urls_to_restore_on_startup"  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}
rule Trojan_BAT_Balamid_A_4{
	meta:
		description = "Trojan:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_80_0 = {62 61 67 6c 61 6e 6d 61 64 69 } //baglanmadi  10
		$a_80_1 = {2f 65 78 63 32 2e 74 78 74 } ///exc2.txt  10
		$a_80_2 = {5c 6c 73 6d 2e 65 78 65 } //\lsm.exe  10
		$a_02_3 = {77 77 77 2e 77 69 6e 74 61 73 6b 90 0f 03 00 2e 63 6f 6d 90 00 } //1
		$a_02_4 = {77 00 77 00 77 00 2e 00 77 00 69 00 6e 00 74 00 61 00 73 00 6b 00 90 0f 01 00 00 90 0f 01 00 00 90 0f 01 00 00 2e 00 63 00 6f 00 6d 00 90 00 } //1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=31
 
}