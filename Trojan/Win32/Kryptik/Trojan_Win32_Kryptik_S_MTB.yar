
rule Trojan_Win32_Kryptik_S_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a d9 8a f9 80 e3 90 01 01 c0 e1 90 01 01 0a 4c 28 90 01 01 80 e7 90 01 01 c0 e3 90 01 01 0a 1c 28 c0 e7 90 01 01 0a 7c 28 90 00 } //01 00 
		$a_02_1 = {8b d3 d3 ea 8b 4c 24 90 01 01 03 54 24 90 01 01 8d 04 19 33 f0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}