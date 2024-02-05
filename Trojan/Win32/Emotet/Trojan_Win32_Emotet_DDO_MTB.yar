
rule Trojan_Win32_Emotet_DDO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a cb 8a c2 f6 d1 f6 d0 0a da 0a c8 be 90 01 04 8b 45 90 01 01 22 cb 8b 5d 90 01 01 88 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}