
rule Trojan_Win32_TrickbotCrypt_SP_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {50 51 ff d7 8b 95 90 01 04 50 8b 85 90 01 04 52 50 e8 90 01 04 8d 8d 90 01 04 8d 95 90 01 04 51 52 6a 02 8b f0 ff 15 90 00 } //02 00 
		$a_03_1 = {50 51 6a 11 ff 15 90 01 04 8b 95 90 01 04 8b 45 90 01 01 8b 8d 90 01 04 83 c4 90 01 01 52 50 51 e8 90 01 04 8b 85 90 01 04 c7 85 90 01 04 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}