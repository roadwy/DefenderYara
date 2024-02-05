
rule PUA_MacOS_Searchproxy_E_MTB{
	meta:
		description = "PUA:MacOS/Searchproxy.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 31 c0 4c 89 f2 4c 89 e1 e8 5a 04 00 00 a8 01 0f 85 c3 00 00 00 49 ff c5 49 21 dd 4c 89 ea 48 c1 ea 06 48 8b 45 d0 48 8b 34 d0 b8 01 00 00 00 44 89 e9 48 d3 e0 4c 0f a3 ee } //01 00 
		$a_01_1 = {64 69 73 70 61 74 63 68 4d 65 73 73 61 67 65 54 6f 53 63 72 69 70 74 } //00 00 
	condition:
		any of ($a_*)
 
}