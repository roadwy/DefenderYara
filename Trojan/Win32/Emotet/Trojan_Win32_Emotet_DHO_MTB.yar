
rule Trojan_Win32_Emotet_DHO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b f0 c1 e6 18 c1 fe 1f c1 e0 1e 81 e6 90 01 04 c1 f8 1f 33 ce 25 90 01 04 33 c1 42 33 c9 8a 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}