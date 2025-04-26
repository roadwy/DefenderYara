
rule Trojan_Win32_RedlineStealer_AMBC_MTB{
	meta:
		description = "Trojan:Win32/RedlineStealer.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ec 04 8b 45 08 8b 4d fc 0f b6 14 08 [0-06] 88 14 08 31 c0 c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 04 8b 45 08 8b 4d fc 0f b6 14 08 81 f2 ?? 00 00 00 88 14 08 31 c0 c7 04 24 00 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}