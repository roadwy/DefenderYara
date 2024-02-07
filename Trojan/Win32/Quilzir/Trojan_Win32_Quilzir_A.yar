
rule Trojan_Win32_Quilzir_A{
	meta:
		description = "Trojan:Win32/Quilzir.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 05 00 00 03 00 "
		
	strings :
		$a_02_0 = {b8 00 5c 26 05 e8 90 01 03 ff 50 e8 90 01 03 ff c3 90 00 } //01 00 
		$a_00_1 = {66 00 61 00 6b 00 65 00 6e 00 61 00 6d 00 65 00 67 00 65 00 6e 00 65 00 72 00 61 00 74 00 6f 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 63 00 3d 00 75 00 73 00 26 00 67 00 65 00 6e 00 3d 00 72 00 61 00 6e 00 64 00 6f 00 6d 00 26 00 6e 00 3d 00 75 00 73 00 } //01 00  fakenamegenerator.com/index.php?c=us&gen=random&n=us
		$a_00_2 = {2e 00 63 00 6f 00 6d 00 2f 00 65 00 6d 00 2f 00 73 00 32 00 2e 00 70 00 68 00 70 00 3f 00 } //01 00  .com/em/s2.php?
		$a_01_3 = {2e 63 6f 6d 2f 65 6d 2f 65 6d 61 69 6c 2e 70 68 70 } //01 00  .com/em/email.php
		$a_01_4 = {00 5a 69 6c 6c 61 00 } //00 00 
	condition:
		any of ($a_*)
 
}