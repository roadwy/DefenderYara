
rule Trojan_Win32_Emotet_DDD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 50 e8 90 01 04 8a 44 24 90 01 01 8a d0 8a cb f6 d2 0a c3 f6 d1 0a d1 22 d0 8b 44 24 90 01 01 88 10 40 83 6c 24 90 02 02 89 44 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}