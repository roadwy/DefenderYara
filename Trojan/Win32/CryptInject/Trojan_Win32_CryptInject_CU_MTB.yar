
rule Trojan_Win32_CryptInject_CU_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {30 33 7c 75 35 90 02 04 7e 91 35 90 02 04 af 00 15 90 02 04 72 01 00 db d2 b1 90 02 04 30 31 3c 90 01 01 72 af 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}