
rule Trojan_Win32_Sabsik_FS_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.FS!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 08 4a 48 00 89 c9 81 c7 01 00 00 00 21 f9 e8 27 00 00 00 89 f9 47 31 10 21 c9 29 f9 81 c1 fc 31 d3 cc 81 c0 02 00 00 00 bf e3 c2 ca b7 39 d8 7c ce } //01 00 
		$a_01_1 = {8d 14 32 4f 21 c9 21 f9 8b 12 29 f9 89 cf 89 f9 81 e2 ff 00 00 00 81 c7 c5 e5 70 71 09 c9 81 e9 01 00 00 00 46 29 c9 81 ef cc 97 a2 f3 29 cf 81 fe f4 01 00 00 75 05 be 00 00 00 00 bf f4 c9 61 ca } //00 00 
	condition:
		any of ($a_*)
 
}