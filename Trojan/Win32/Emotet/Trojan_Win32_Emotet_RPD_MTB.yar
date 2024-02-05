
rule Trojan_Win32_Emotet_RPD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RPD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 10 2b fe 8a 0c 1f 32 d1 8b 4c 24 4c 88 10 8b 44 24 20 40 3b c1 } //00 00 
	condition:
		any of ($a_*)
 
}