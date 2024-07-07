
rule Trojan_Win32_Azorult_RPX_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 6c 24 14 8d 0c 17 89 4c 24 24 8b 4c 24 1c d3 ea 89 54 24 18 8b 44 24 34 01 44 24 18 8b 44 24 24 31 44 24 14 8b 4c 24 14 33 4c 24 18 8d 44 24 28 89 4c 24 14 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}