
rule Trojan_Win32_Azorult_AF_MTB{
	meta:
		description = "Trojan:Win32/Azorult.AF!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 c7 45 fc 02 00 00 00 8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d fc 31 08 c9 } //5
		$a_01_1 = {55 8b ec 51 83 65 fc 00 83 45 fc 04 8b 4d fc 8b 45 0c d3 e0 8b 4d 08 89 01 c9 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}