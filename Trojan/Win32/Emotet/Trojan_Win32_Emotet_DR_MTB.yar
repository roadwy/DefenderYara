
rule Trojan_Win32_Emotet_DR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DR!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 6c 24 40 8b 44 24 14 2b d3 03 d5 8b 6c 24 48 8a 14 2a 30 14 38 } //00 00 
	condition:
		any of ($a_*)
 
}