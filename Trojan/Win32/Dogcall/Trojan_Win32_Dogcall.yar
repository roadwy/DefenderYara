
rule Trojan_Win32_Dogcall{
	meta:
		description = "Trojan:Win32/Dogcall,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 69 6e 61 6c 31 73 74 73 70 79 5c 68 61 64 6f 77 65 78 65 63 75 74 65 20 2d 20 43 6f 70 79 5c 52 65 6c 65 61 73 65 5c 68 61 64 6f 77 65 78 65 63 75 74 65 2e 70 64 62 } //01 00 
		$a_01_1 = {25 73 3f 4d 61 63 68 69 6e 65 49 64 3d 25 73 26 49 6e 66 6f 53 6f 3d 25 73 26 49 6e 64 65 78 3d 25 73 26 41 63 63 6f 75 6e 74 3d 25 73 26 47 72 6f 75 70 3d 25 73 } //00 00 
	condition:
		any of ($a_*)
 
}