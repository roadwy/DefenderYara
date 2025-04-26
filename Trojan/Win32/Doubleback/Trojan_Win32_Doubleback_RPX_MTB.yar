
rule Trojan_Win32_Doubleback_RPX_MTB{
	meta:
		description = "Trojan:Win32/Doubleback.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 75 c4 50 89 e6 89 75 c8 50 89 e6 89 75 cc 50 89 e6 89 75 d0 50 89 e6 89 75 d4 50 89 e6 89 75 d8 8b 75 9c c7 06 00 00 00 00 8b 75 84 89 31 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}