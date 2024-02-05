
rule Trojan_Win32_Coroxy_MB_MTB{
	meta:
		description = "Trojan:Win32/Coroxy.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {7f d5 7c 75 77 cb 49 6c 72 c8 6b 00 96 a7 08 00 96 a7 5e 69 64 d3 7d 61 72 e1 7a 65 73 a7 08 00 96 a7 08 00 96 f2 66 6d 37 d7 5e 69 33 d0 47 66 } //05 00 
		$a_01_1 = {c3 6d 48 b7 c5 6c 6c b3 e8 08 00 96 ee 6d 74 db c6 6c 75 b2 cc 40 61 a8 cb 64 65 69 a7 08 00 55 d9 6d 61 8a cc 4e 69 6a cc 49 00 96 a7 08 00 96 } //00 00 
	condition:
		any of ($a_*)
 
}