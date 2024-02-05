
rule Trojan_Win32_CryptMari_SA_MTB{
	meta:
		description = "Trojan:Win32/CryptMari.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b c6 99 f7 f9 8a 04 1a 8b 55 f8 30 04 16 46 3b f7 7c } //01 00 
		$a_02_1 = {5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 63 72 70 74 72 5c 62 61 73 65 5c 90 02 02 5c 73 74 75 62 5c 52 65 6c 65 61 73 65 5c 73 74 75 62 2e 70 64 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}