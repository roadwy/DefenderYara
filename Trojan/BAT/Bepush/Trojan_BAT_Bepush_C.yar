
rule Trojan_BAT_Bepush_C{
	meta:
		description = "Trojan:BAT/Bepush.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {4b 69 6c 6c 43 68 72 6f 6d 65 } //KillChrome  01 00 
		$a_80_1 = {4b 69 6c 6c 46 69 72 65 66 6f 78 } //KillFirefox  01 00 
		$a_80_2 = {2f 65 78 74 46 69 6c 65 73 } ///extFiles  01 00 
		$a_80_3 = {75 73 65 72 5f 70 72 65 66 28 22 62 72 6f 77 73 65 72 2e 73 74 61 72 74 75 70 2e 68 6f 6d 65 70 61 67 65 22 } //user_pref("browser.startup.homepage"  00 00 
	condition:
		any of ($a_*)
 
}