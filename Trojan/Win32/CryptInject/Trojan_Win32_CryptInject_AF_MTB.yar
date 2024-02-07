
rule Trojan_Win32_CryptInject_AF_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 6f 74 5c 77 6f 72 6b 5c 74 68 72 6f 77 5c 68 6f 74 5c 4c 6f 67 5c 4f 66 74 65 6e 72 65 70 72 65 73 65 6e 74 2e 70 64 62 } //00 00  Hot\work\throw\hot\Log\Oftenrepresent.pdb
	condition:
		any of ($a_*)
 
}