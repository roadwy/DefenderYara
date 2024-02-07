
rule TrojanClicker_BAT_Balamid_A{
	meta:
		description = "TrojanClicker:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {5c 63 73 72 73 73 2e 65 78 65 } //\csrss.exe  01 00 
		$a_80_1 = {62 61 67 6c 61 6e 6d 61 64 69 } //baglanmadi  01 00 
		$a_80_2 = {2f 74 6f 79 32 2e 74 78 74 } ///toy2.txt  01 00 
		$a_80_3 = {6f 6e 6d 6f 75 73 65 64 6f 77 6e } //onmousedown  00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanClicker_BAT_Balamid_A_2{
	meta:
		description = "TrojanClicker:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 72 65 6b 6c 61 6d 2f 37 32 38 78 39 30 2e 68 74 6d 6c } ///reklam/728x90.html  01 00 
		$a_80_1 = {61 6b 65 65 67 6c 65 65 6e 61 6f 6e 64 63 6b 6b 6e 6c 68 66 6c 6d 69 68 66 67 6b 70 62 61 6e 65 } //akeegleenaondckknlhflmihfgkpbane  00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanClicker_BAT_Balamid_A_3{
	meta:
		description = "TrojanClicker:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {5c 74 61 73 6b 36 34 2e 65 78 65 } //\task64.exe  01 00 
		$a_80_1 = {5c 73 79 73 74 65 6d 2e 65 78 65 } //\system.exe  01 00 
		$a_80_2 = {77 69 6e 74 61 73 6b 33 32 2e 63 6f 6d } //wintask32.com  01 00 
		$a_80_3 = {2f 74 6f 79 32 2e 74 78 74 } ///toy2.txt  00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanClicker_BAT_Balamid_A_4{
	meta:
		description = "TrojanClicker:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {2f 72 65 6b 6c 61 6d 2f 90 05 04 03 30 2d 39 78 90 05 04 03 30 2d 39 2e 68 74 6d 90 00 } //01 00 
		$a_02_1 = {2f 00 72 00 65 00 6b 00 6c 00 61 00 6d 00 2f 90 05 08 04 00 30 2d 39 00 78 90 05 08 04 00 30 2d 39 00 2e 00 68 00 74 00 6d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanClicker_BAT_Balamid_A_5{
	meta:
		description = "TrojanClicker:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {2f 72 65 6b 6c 61 6d 2f 37 32 38 78 39 30 2e 68 74 6d 6c } ///reklam/728x90.html  01 00 
		$a_80_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //\Microsoft\Windows\CurrentVersion\Run  01 00 
		$a_80_2 = {63 68 72 6f 6d 65 } //chrome  01 00 
		$a_80_3 = {73 61 66 61 72 69 } //safari  01 00 
		$a_80_4 = {66 69 72 65 66 6f 78 } //firefox  00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanClicker_BAT_Balamid_A_6{
	meta:
		description = "TrojanClicker:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 65 00 63 00 20 00 73 00 61 00 61 00 74 00 } //01 00  exec saat
		$a_01_1 = {59 00 61 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 } //01 00  YaBrowser
		$a_01_2 = {65 00 78 00 65 00 63 00 20 00 75 00 79 00 65 00 6d 00 63 00 6b 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 20 00 40 00 6d 00 61 00 63 00 } //01 00  exec uyemckontrol @mac
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {42 61 73 6c 61 74 5f 43 6c 69 63 6b 00 } //01 00 
		$a_01_5 = {44 75 72 64 75 72 5f 43 6c 69 63 6b 00 } //01 00 
		$a_01_6 = {2f 00 74 00 6f 00 79 00 2e 00 74 00 78 00 74 00 } //00 00  /toy.txt
		$a_00_7 = {7e 15 00 00 } //b5 3c 
	condition:
		any of ($a_*)
 
}