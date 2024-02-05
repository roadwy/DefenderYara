
rule Trojan_Win32_Trikbot_AA_MTB{
	meta:
		description = "Trojan:Win32/Trikbot.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 8b 01 51 8b 0a 33 c1 59 52 8b d0 51 03 cf 51 58 89 10 59 5a 58 42 42 42 42 3b 55 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}