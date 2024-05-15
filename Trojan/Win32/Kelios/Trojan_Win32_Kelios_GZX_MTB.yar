
rule Trojan_Win32_Kelios_GZX_MTB{
	meta:
		description = "Trojan:Win32/Kelios.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {89 40 9c 6c 1c b6 34 f6 bc 90 01 04 5c 70 ea 31 06 64 e5 a5 56 90 00 } //05 00 
		$a_01_1 = {33 d4 66 2b d5 0f b7 d1 0f b6 16 66 a9 9a 2e 66 85 ce 8d b6 01 00 00 00 32 d3 } //00 00 
	condition:
		any of ($a_*)
 
}