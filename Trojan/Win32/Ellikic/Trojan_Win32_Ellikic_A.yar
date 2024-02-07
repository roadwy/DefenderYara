
rule Trojan_Win32_Ellikic_A{
	meta:
		description = "Trojan:Win32/Ellikic.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 45 f8 0f b6 44 38 ff 66 03 f0 66 69 c6 be 15 66 05 51 7e 8b f0 43 fe 4d f7 75 c1 } //01 00 
		$a_01_1 = {3c 69 66 72 61 6d 65 20 73 72 63 3d 22 25 73 22 20 77 69 64 74 68 3d 30 20 68 65 69 67 68 74 3d 30 3e 3c 2f 69 66 72 61 6d 65 3e } //01 00  <iframe src="%s" width=0 height=0></iframe>
		$a_01_2 = {69 65 68 65 6c 70 65 72 2e 64 6c 6c 00 44 6c 6c } //00 00  敩敨灬牥搮汬䐀汬
	condition:
		any of ($a_*)
 
}