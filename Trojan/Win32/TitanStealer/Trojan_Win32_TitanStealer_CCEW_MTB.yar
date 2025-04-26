
rule Trojan_Win32_TitanStealer_CCEW_MTB{
	meta:
		description = "Trojan:Win32/TitanStealer.CCEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 03 55 fc 0f b6 02 89 45 f8 8b 4d 08 03 4d fc 0f b6 11 33 55 f4 8b 45 08 03 45 fc 88 10 8b 4d f8 89 4d f4 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}