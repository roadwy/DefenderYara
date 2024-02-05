
rule Trojan_Win32_Gozi_GEE_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 45 e8 be 90 01 04 8d 7d 90 01 01 a5 a5 a5 8b 55 90 01 01 33 55 90 01 01 8d 71 90 01 01 03 55 90 01 01 8b ce 03 55 90 02 06 d3 ea 52 8b 55 90 01 01 8d 0c 02 e8 90 01 04 8b 4d 90 01 01 8b 41 90 01 01 2b 41 90 01 01 81 45 90 01 01 00 10 00 00 03 41 90 01 01 8b ce 3b cb a3 90 01 04 72 90 00 } //0a 00 
		$a_02_1 = {03 c6 89 01 8b f7 83 c1 04 90 02 04 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}