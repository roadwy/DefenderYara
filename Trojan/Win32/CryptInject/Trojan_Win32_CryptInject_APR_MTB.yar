
rule Trojan_Win32_CryptInject_APR_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.APR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 a3 e1 11 6a 01 ff 15 90 01 01 00 01 10 90 00 } //01 00 
		$a_03_1 = {01 10 0f b6 05 90 01 02 01 10 c1 f8 06 0f b6 0d 90 01 02 01 10 c1 e1 02 0b c1 a2 90 01 02 01 10 0f b6 90 01 03 01 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}