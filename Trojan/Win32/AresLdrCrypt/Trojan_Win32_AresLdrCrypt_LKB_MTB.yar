
rule Trojan_Win32_AresLdrCrypt_LKB_MTB{
	meta:
		description = "Trojan:Win32/AresLdrCrypt.LKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b d0 8a 84 3a 90 01 04 8b 54 24 90 01 01 32 04 11 8b 54 24 90 01 01 88 04 16 47 41 46 3b 7c 24 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}