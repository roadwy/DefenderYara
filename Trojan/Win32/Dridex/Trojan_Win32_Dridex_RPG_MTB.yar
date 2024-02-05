
rule Trojan_Win32_Dridex_RPG_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 1c 37 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d0 88 1c 31 81 c6 01 00 00 00 8b 4d f0 39 ce 8b 4d cc } //00 00 
	condition:
		any of ($a_*)
 
}