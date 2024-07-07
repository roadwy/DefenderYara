
rule Trojan_Win32_Amadey_NEAB_MTB{
	meta:
		description = "Trojan:Win32/Amadey.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 03 45 d4 89 45 fc 8b 45 e8 03 55 d0 03 90 01 01 89 45 f0 8b 45 f0 31 45 fc 31 55 fc 90 00 } //5
		$a_03_1 = {8b 45 fc 29 45 f8 81 45 e8 47 86 c8 61 ff 4d e0 0f 85 90 01 01 fe ff ff 8b 45 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}