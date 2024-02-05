
rule Trojan_Win32_Delf_NC{
	meta:
		description = "Trojan:Win32/Delf.NC,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {99 5b f7 fb 85 d2 75 0f } //01 00 
		$a_01_1 = {6d 61 63 3d 25 73 26 50 63 54 79 70 65 3d 25 73 26 41 76 4e 61 6d 65 3d } //01 00 
		$a_01_2 = {76 69 70 2e 65 6c 6f 61 7a 2e 63 6f 6d 2f 61 64 6d 69 6e } //02 00 
		$a_01_3 = {6d 75 74 65 78 5f 73 65 6e 64 64 61 74 61 5f 2e 6c 61 } //00 00 
	condition:
		any of ($a_*)
 
}