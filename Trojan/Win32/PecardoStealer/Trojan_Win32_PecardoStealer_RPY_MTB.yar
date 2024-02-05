
rule Trojan_Win32_PecardoStealer_RPY_MTB{
	meta:
		description = "Trojan:Win32/PecardoStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {31 45 f8 ff 25 90 01 04 cc ff 30 e8 90 01 04 59 a1 90 01 04 cc e8 90 01 04 50 55 c3 cc aa 68 90 01 04 c3 e9 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}