
rule Trojan_Win32_RedLineStealer_A_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {88 55 ff 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 88 45 ff 8b 55 ec 8a 45 ff 88 44 15 d0 e9 dd fe ff ff } //00 00 
	condition:
		any of ($a_*)
 
}