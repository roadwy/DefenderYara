
rule Trojan_Win32_Swisyn_ARAZ_MTB{
	meta:
		description = "Trojan:Win32/Swisyn.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 8d 54 24 14 6a 04 52 6a 04 6a 00 68 cc c1 b0 00 50 89 7c 24 2c ff d6 8b 54 24 10 8d 4c 24 14 6a 04 51 6a 04 6a 00 68 c0 c1 b0 00 52 c7 44 24 2c 03 00 00 00 ff d6 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}