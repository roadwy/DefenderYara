
rule Trojan_Win32_Lokibot_HYJK_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.HYJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 00 32 00 74 00 57 00 50 00 6a 00 63 00 65 00 4b 00 39 00 72 00 4c } //00 00 
	condition:
		any of ($a_*)
 
}