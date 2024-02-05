
rule Trojan_Win64_TxRloader_B_dha{
	meta:
		description = "Trojan:Win64/TxRloader.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 64 00 "
		
	strings :
		$a_43_0 = {c0 26 2b c8 0f 90 01 04 41 32 48 ff f6 d1 41 88 48 ff 3b fe 72 90 00 00 } //00 5d 
	condition:
		any of ($a_*)
 
}