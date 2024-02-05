
rule Trojan_Win64_Emotet_PAT_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b ce 2b c8 48 63 c1 8a 4c 04 90 01 01 48 8b 05 90 02 04 44 8a 14 02 ba 90 02 04 8b 05 90 01 04 44 32 d1 0f af 90 02 06 2b d0 90 02 a0 48 63 c8 44 88 14 19 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}