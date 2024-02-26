
rule Trojan_Win32_FatalRAT_B_MTB{
	meta:
		description = "Trojan:Win32/FatalRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {c2 30 54 3e 90 01 01 46 3b b5 90 09 1b 00 8a 44 3e 90 01 01 32 85 90 01 02 ff ff 88 44 3e 90 01 01 e8 90 01 04 99 f7 bd 90 01 02 ff ff fe 90 00 } //02 00 
		$a_03_1 = {8a 04 3e 32 85 90 01 02 ff ff 88 04 3e e8 90 01 04 99 f7 bd 90 01 02 ff ff fe c2 30 14 3e 46 3b b5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}