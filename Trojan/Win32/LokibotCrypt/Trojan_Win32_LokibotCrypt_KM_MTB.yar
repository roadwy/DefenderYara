
rule Trojan_Win32_LokibotCrypt_KM_MTB{
	meta:
		description = "Trojan:Win32/LokibotCrypt.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {04 31 81 3d 90 01 04 03 02 00 00 75 90 01 01 53 53 ff 15 90 01 04 89 1d 90 01 04 46 3b 35 90 01 04 72 90 09 13 00 a1 90 01 04 8a 84 30 90 01 04 8b 0d 90 01 04 88 90 00 } //01 00 
		$a_02_1 = {30 04 3b 83 7d 90 01 01 19 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}