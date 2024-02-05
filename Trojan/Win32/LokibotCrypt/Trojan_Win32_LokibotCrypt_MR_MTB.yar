
rule Trojan_Win32_LokibotCrypt_MR_MTB{
	meta:
		description = "Trojan:Win32/LokibotCrypt.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {3b c7 7c c3 90 0a 41 00 69 90 02 05 89 90 02 05 89 90 02 05 81 90 02 09 8b 90 02 05 03 90 02 05 40 89 90 02 05 8a 90 02 05 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}