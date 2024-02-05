
rule Trojan_Win32_Staser_ASR_MTB{
	meta:
		description = "Trojan:Win32/Staser.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c7 8b cf c1 f8 05 83 e1 1f 8b 04 85 e0 68 08 01 8d 04 c8 8b 0b 89 08 8a 4d 00 88 48 04 47 45 83 c3 04 3b fe } //00 00 
	condition:
		any of ($a_*)
 
}