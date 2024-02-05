
rule Trojan_Win32_Amadey_GNS_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 41 6d 61 64 65 79 5c 52 65 6c 65 61 73 65 5c 41 6d 61 64 65 79 2e 70 64 62 } //01 00 
		$a_80_1 = {78 6d 73 63 6f 72 65 65 2e 64 6c 6c } //xmscoree.dll  01 00 
		$a_01_2 = {65 43 52 33 35 4b 4d 30 47 6f 30 } //01 00 
		$a_01_3 = {4d 78 39 58 4d 6c 41 63 } //01 00 
		$a_01_4 = {5a 68 6c 6e 52 5a 39 44 4d 71 3d 3d } //01 00 
		$a_01_5 = {59 56 4e 4c 4e 48 46 4e 4e 52 45 3d } //01 00 
		$a_01_6 = {59 43 4a 79 52 36 4a 62 37 4e 45 3d } //00 00 
	condition:
		any of ($a_*)
 
}