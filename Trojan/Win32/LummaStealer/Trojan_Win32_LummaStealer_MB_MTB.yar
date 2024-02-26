
rule Trojan_Win32_LummaStealer_MB_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {89 4c 3c 14 0f b6 44 3e 02 c1 e0 10 09 c8 89 44 3c 14 0f b6 4c 3e 03 c1 e1 18 09 c1 89 4c 3c 14 83 c7 04 } //05 00 
		$a_01_1 = {0f b6 3c 02 89 d9 80 e1 18 d3 e7 89 c1 83 e1 fc 31 7c 0c 14 40 83 c3 08 39 c6 75 } //00 00 
	condition:
		any of ($a_*)
 
}