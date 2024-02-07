
rule Trojan_Win32_Mejdho_A{
	meta:
		description = "Trojan:Win32/Mejdho.A,SIGNATURE_TYPE_PEHSTR_EXT,19 00 17 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {6a 02 6a 00 6a c4 ff b5 ac fe ff ff ff 15 90 01 03 00 83 65 ec 00 6a 00 8d 45 ec 50 6a 3c 8d 85 b0 fe ff ff 50 ff b5 ac fe ff ff ff 15 90 00 } //0a 00 
		$a_02_1 = {74 35 68 44 10 00 00 ff 75 10 e8 90 01 03 00 59 59 6a 00 8d 45 f8 50 68 44 10 00 00 ff 75 10 ff 75 d4 ff 15 90 01 03 00 68 44 10 00 00 ff 75 10 e8 90 01 03 00 59 59 90 00 } //01 00 
		$a_00_2 = {5c 53 56 43 48 4f 53 54 2e 45 58 45 } //01 00  \SVCHOST.EXE
		$a_00_3 = {6d 79 67 75 69 64 } //01 00  myguid
		$a_00_4 = {6d 79 70 61 72 65 6e 74 74 68 72 65 61 64 69 64 } //01 00  myparentthreadid
		$a_00_5 = {47 6c 6f 62 61 6c 5c 70 73 } //01 00  Global\ps
		$a_00_6 = {2e 65 78 65 00 00 00 00 2e 73 63 6f 00 00 00 00 2e 70 72 6f 00 00 00 00 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}