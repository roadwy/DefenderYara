
rule Trojan_Win32_Kryptik_PRD_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.PRD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 e8 e9 d6 fc 5d 29 d2 81 c1 01 00 00 00 83 ec 04 c7 04 24 fc 4e f2 e2 5a 09 c2 81 f9 f4 01 00 00 75 05 b9 00 00 00 00 68 cb a4 60 7e 5a 83 ec 04 89 14 24 58 09 d0 } //00 00 
	condition:
		any of ($a_*)
 
}