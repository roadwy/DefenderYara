
rule Trojan_Win32_Myspamce_A{
	meta:
		description = "Trojan:Win32/Myspamce.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {ff d7 8b 45 d4 68 90 01 02 40 00 50 ff 15 90 01 02 40 00 59 85 c0 59 75 6e 39 5d c4 75 69 90 00 } //02 00 
		$a_01_1 = {3f 61 3d 25 73 26 62 3d 25 73 } //02 00 
		$a_01_2 = {6d 79 73 70 61 63 65 74 75 62 65 2e 6e 65 74 } //01 00 
		$a_01_3 = {f7 f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 6d 79 73 70 61 63 65 2e 63 6f 6d 00 } //01 00 
		$a_01_4 = {66 72 69 65 6e 64 69 64 3d 36 32 32 31 00 } //00 00 
	condition:
		any of ($a_*)
 
}