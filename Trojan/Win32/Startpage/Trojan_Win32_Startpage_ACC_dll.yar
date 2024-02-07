
rule Trojan_Win32_Startpage_ACC_dll{
	meta:
		description = "Trojan:Win32/Startpage.ACC!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 61 61 32 33 34 2e 63 6f 6d } //01 00  aaa234.com
		$a_01_1 = {2e 73 62 31 37 33 2e 63 6f 6d 2f 3f } //01 00  .sb173.com/?
		$a_01_2 = {2e 67 61 6d 65 31 31 32 32 2e 63 6f 6d 2f 3f } //01 00  .game1122.com/?
		$a_03_3 = {63 3a 5c 66 77 65 2e 6c 6f 67 90 01 0a 79 79 79 79 6d 6d 64 64 90 01 0c 63 3a 5c 66 6a 65 69 2e 6c 6f 67 90 00 } //01 00 
		$a_03_4 = {6e 65 74 32 38 37 2e 63 6e 90 01 0b 77 7a 31 31 32 32 2e 63 6f 6d 90 01 0a 71 71 31 39 34 39 2e 6e 65 74 90 00 } //01 00 
		$a_01_5 = {56 61 67 61 61 cd db b8 c2 bb ad ca b1 b4 fa 00 } //00 00 
	condition:
		any of ($a_*)
 
}