
rule Trojan_Win32_CryptRan_SA_MTB{
	meta:
		description = "Trojan:Win32/CryptRan.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 03 32 06 46 4f 75 90 01 01 be 90 01 04 bf 09 00 00 00 88 03 83 f9 00 74 90 01 01 4b 49 eb 90 00 } //01 00 
		$a_00_1 = {63 73 72 66 63 79 63 74 63 74 63 63 63 63 73 2e 73 69 65 } //00 00  csrfcyctctccccs.sie
	condition:
		any of ($a_*)
 
}