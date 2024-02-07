
rule Trojan_Win32_Koobface_gen_M{
	meta:
		description = "Trojan:Win32/Koobface.gen!M,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {3f 61 63 74 69 6f 6e 3d 62 73 26 76 3d 32 30 26 61 3d 90 03 05 0a 6e 61 6d 65 73 67 65 74 75 6e 72 65 61 64 79 90 00 } //01 00 
		$a_00_1 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0a 20 64 65 6c 20 22 25 73 22 } //01 00 
		$a_02_2 = {62 6c 6f 67 90 02 10 2e 63 6f 6d 90 00 } //01 00 
		$a_00_3 = {23 42 4c 41 43 4b 4c 41 42 45 4c } //00 00  #BLACKLABEL
	condition:
		any of ($a_*)
 
}