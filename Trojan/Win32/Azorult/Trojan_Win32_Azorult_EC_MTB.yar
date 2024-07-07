
rule Trojan_Win32_Azorult_EC_MTB{
	meta:
		description = "Trojan:Win32/Azorult.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 8b 4d 08 8b 45 0c 83 65 fc 00 89 01 8b 45 0c 33 45 fc 89 45 fc 8b 45 fc 89 01 c9 c2 0c 00 8b 44 24 04 8b 4c 24 08 31 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}