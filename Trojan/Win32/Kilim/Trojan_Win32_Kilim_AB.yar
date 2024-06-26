
rule Trojan_Win32_Kilim_AB{
	meta:
		description = "Trojan:Win32/Kilim.AB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 61 62 6c 65 4c 55 41 00 00 00 43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00 00 } //01 00 
		$a_03_1 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 90 02 06 68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 63 68 72 6f 6d 65 90 00 } //01 00 
		$a_03_2 = {41 75 74 6f 55 70 64 61 74 65 43 68 65 63 6b 50 65 72 69 6f 64 4d 69 6e 75 74 65 73 90 02 08 44 69 73 61 62 6c 65 41 75 74 6f 55 70 64 61 74 65 43 68 65 63 6b 73 43 68 65 63 6b 62 6f 78 56 61 6c 75 65 90 00 } //01 00 
		$a_01_3 = {2e 78 79 7a 2f 65 78 65 2f 64 65 66 61 75 6c 74 5f 61 70 70 73 2f } //01 00  .xyz/exe/default_apps/
		$a_01_4 = {5c 64 72 69 76 65 2e 63 72 78 } //01 00  \drive.crx
		$a_01_5 = {5c 65 78 74 65 72 6e 61 6c 5f 65 78 74 65 6e 73 69 6f 6e 73 2e 6a 73 6f 6e } //01 00  \external_extensions.json
		$a_01_6 = {5c 53 65 63 75 72 65 20 50 72 65 66 65 72 65 6e 63 65 73 } //00 00  \Secure Preferences
		$a_00_7 = {78 64 01 00 08 } //00 08 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Kilim_AB_2{
	meta:
		description = "Trojan:Win32/Kilim.AB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 61 62 6c 65 4c 55 41 00 00 00 43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00 00 } //01 00 
		$a_01_1 = {67 6f 6f 2e 67 6c 2f 64 6b 44 67 74 39 } //01 00  goo.gl/dkDgt9
		$a_01_2 = {2d 2d 6c 6f 61 64 2d 63 6f 6d 70 6f 6e 65 6e 74 2d 65 78 74 65 6e 73 69 6f 6e 3d 22 } //01 00  --load-component-extension="
		$a_01_3 = {00 4a 53 00 00 5c 62 61 63 6b 67 72 6f 75 6e 64 2e 6a 73 } //01 00 
		$a_01_4 = {00 5c 6a 71 75 65 72 79 2e 6d 69 6e 2e 6a 73 00 } //01 00  尀煪敵祲洮湩樮s
		$a_01_5 = {5c 63 68 72 6f 6d 69 75 6d 2e 65 78 65 00 00 00 5c 63 68 72 6f 6d 65 2e 65 78 65 } //01 00 
		$a_03_6 = {41 75 74 6f 55 70 64 61 74 65 43 68 65 63 6b 50 65 72 69 6f 64 4d 69 6e 75 74 65 73 90 02 08 44 69 73 61 62 6c 65 41 75 74 6f 55 70 64 61 74 65 43 68 65 63 6b 73 43 68 65 63 6b 62 6f 78 56 61 6c 75 65 90 00 } //01 00 
		$a_03_7 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 90 02 06 68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 63 68 72 6f 6d 65 90 00 } //01 00 
		$a_01_8 = {23 31 31 34 00 00 00 00 68 74 74 70 73 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 63 68 72 6f 6d 65 } //00 00 
		$a_00_9 = {5d 04 00 00 d2 } //43 03 
	condition:
		any of ($a_*)
 
}