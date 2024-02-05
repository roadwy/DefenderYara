
rule Trojan_Win64_Emotet_DO_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 41 03 d0 41 ff c0 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b c2 2f 2b c8 48 63 c1 48 8d 0d 90 02 04 8a 04 08 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}