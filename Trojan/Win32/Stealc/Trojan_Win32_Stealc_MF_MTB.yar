
rule Trojan_Win32_Stealc_MF_MTB{
	meta:
		description = "Trojan:Win32/Stealc.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 3b 45 0c 73 90 01 01 8b 4d 08 03 4d fc 0f b6 11 89 55 f8 8b 45 08 03 45 fc 0f b6 08 33 4d f4 8b 55 08 03 55 fc 88 0a 8b 45 f8 89 45 f4 eb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}