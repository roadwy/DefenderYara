
rule Trojan_Win32_Neoreblamy_BAI_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 fc 50 e8 ?? ?? ?? ff 59 59 8b 4d 14 8b 49 04 0f b6 04 01 50 8b 45 10 03 45 fc 8b 4d 14 8b 09 0f b6 04 01 50 e8 ?? ?? ?? ff 59 59 50 8d 4d e4 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}