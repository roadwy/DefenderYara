
rule Trojan_Win32_Affpach_A{
	meta:
		description = "Trojan:Win32/Affpach.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 43 43 38 45 42 43 37 2d 43 46 44 44 2d 34 42 41 30 2d 41 31 44 31 2d 46 34 41 46 42 38 35 35 41 37 31 35 } //01 00  3CC8EBC7-CFDD-4BA0-A1D1-F4AFB855A715
		$a_01_1 = {64 6f 63 75 6d 65 6e 74 2e 67 65 74 45 6c 65 6d 65 6e 74 42 79 49 64 28 27 73 75 27 29 2e 72 65 6d 6f 76 65 4e 6f 64 65 28 74 72 75 65 29 } //01 00  document.getElementById('su').removeNode(true)
		$a_01_2 = {49 45 54 41 53 4b 2e 70 64 62 } //01 00  IETASK.pdb
		$a_01_3 = {2f 67 6f 2f 61 63 74 2f 6d 6d 62 64 2f 70 64 30 31 2e 70 68 70 3f 70 69 64 3d } //01 00  /go/act/mmbd/pd01.php?pid=
		$a_01_4 = {26 63 68 3d 35 26 62 61 72 3d 26 77 64 3d 00 } //00 00 
	condition:
		any of ($a_*)
 
}