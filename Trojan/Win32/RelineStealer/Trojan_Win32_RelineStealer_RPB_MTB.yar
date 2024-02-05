
rule Trojan_Win32_RelineStealer_RPB_MTB{
	meta:
		description = "Trojan:Win32/RelineStealer.RPB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 95 2c f6 ff ff 21 ca 89 8d 04 f6 ff ff 8b 8d 2c f6 ff ff 89 95 00 f6 ff ff 8b 95 04 f6 ff ff 31 d1 8b 95 00 f6 ff ff 09 ca 88 d1 8b 95 a4 f8 ff ff 88 0c 13 } //00 00 
	condition:
		any of ($a_*)
 
}