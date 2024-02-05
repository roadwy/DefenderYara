
rule Trojan_Win32_Chiviper_C{
	meta:
		description = "Trojan:Win32/Chiviper.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 08 2a ca 32 ca 88 08 40 4e 75 f4 } //02 00 
		$a_03_1 = {8b f0 6a 7c 56 e8 90 01 04 83 c4 0c 85 c0 0f 84 90 01 02 00 00 83 c6 06 90 00 } //02 00 
		$a_03_2 = {6a 02 6a 00 68 0c fe ff ff 56 ff 15 90 01 04 68 f4 01 00 00 e8 d6 12 00 00 83 c4 04 8d 54 24 08 8b f8 6a 00 52 68 f4 01 00 00 57 56 ff 15 90 00 } //01 00 
		$a_01_3 = {6d 61 63 3d 25 73 26 76 65 72 3d } //00 00 
	condition:
		any of ($a_*)
 
}