
rule Trojan_Win32_InjectorCrypt_SL_MTB{
	meta:
		description = "Trojan:Win32/InjectorCrypt.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 00 89 45 90 01 01 83 7d 90 01 01 00 74 02 eb 02 eb 90 01 01 6a 00 6a 01 8b 45 90 01 01 ff 70 90 01 01 ff 55 90 01 01 83 45 90 01 01 04 eb 90 01 01 c9 c3 90 00 } //02 00 
		$a_03_1 = {58 50 83 e8 90 01 01 c3 8b 45 90 01 01 e8 90 01 04 8b 55 90 01 01 8b 45 90 01 01 e8 90 01 04 8b 45 90 01 01 e8 90 01 04 8b 45 90 01 01 e8 90 01 04 8b 45 90 01 01 e8 90 01 04 8b 45 90 01 01 e8 90 01 04 c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}