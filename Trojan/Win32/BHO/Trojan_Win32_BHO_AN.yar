
rule Trojan_Win32_BHO_AN{
	meta:
		description = "Trojan:Win32/BHO.AN,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 79 63 67 5f 4d 61 69 6e } //01 00  hycg_Main
		$a_01_1 = {45 78 70 6c 6f 72 65 72 20 42 61 72 73 5c 7b 31 36 31 46 33 38 35 37 2d 43 44 38 36 2d 34 39 34 36 2d 42 32 41 42 2d 35 41 33 35 42 43 46 46 38 39 30 35 7d } //01 00  Explorer Bars\{161F3857-CD86-4946-B2AB-5A35BCFF8905}
		$a_01_2 = {5c 64 74 74 64 } //01 00  \dttd
		$a_01_3 = {73 20 27 49 45 48 65 6c 70 65 72 20 42 61 6e 64 27 } //01 00  s 'IEHelper Band'
		$a_01_4 = {55 52 53 4f 46 54 20 57 33 32 44 41 53 4d 00 2d 3d 43 48 49 4e 41 20 43 52 41 43 4b 49 4e 47 20 47 52 4f 55 50 3d 2d 00 4f 6c 6c 79 44 62 67 00 54 52 57 32 30 30 30 } //01 00 
		$a_01_5 = {4e 54 69 63 65 2e 73 79 73 } //01 00  NTice.sys
		$a_01_6 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //00 00  NtQuerySystemInformation
	condition:
		any of ($a_*)
 
}