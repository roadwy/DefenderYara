
rule Trojan_BAT_LockScreen_G_MTB{
	meta:
		description = "Trojan:BAT/LockScreen.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 35 00 39 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 6d 00 79 00 2f } //01 00 
		$a_80_1 = {63 61 6c 6c 5f 77 65 62 5f 70 61 67 65 5f 74 61 73 6b 62 61 72 } //call_web_page_taskbar  01 00 
		$a_80_2 = {72 75 6e 54 65 61 6d 56 69 65 77 65 72 5f 53 65 74 75 70 } //runTeamViewer_Setup  01 00 
		$a_80_3 = {72 75 6e 41 6e 79 44 65 73 6b } //runAnyDesk  01 00 
		$a_80_4 = {59 6f 75 72 20 70 72 6f 64 75 63 74 20 6b 65 79 20 73 68 6f 75 6c 64 20 62 65 20 69 6e 20 61 6e 20 65 6d 61 69 6c 20 66 72 6f 6d 20 77 68 6f 65 76 65 72 20 73 6f 6c 64 20 6f 72 20 64 69 73 74 72 69 62 75 74 65 64 20 57 69 6e 64 6f 77 73 20 74 6f 20 79 6f 75 20 6f 72 20 6f 6e } //Your product key should be in an email from whoever sold or distributed Windows to you or on  01 00 
		$a_80_5 = {54 68 65 20 70 72 6f 64 75 63 74 20 6b 65 79 20 6c 6f 6f 6b 73 20 73 69 6d 69 6c 61 72 20 74 6f 20 74 68 69 73 3a 2e 2e 50 52 4f 44 55 43 54 20 4b 45 59 } //The product key looks similar to this:..PRODUCT KEY  00 00 
	condition:
		any of ($a_*)
 
}