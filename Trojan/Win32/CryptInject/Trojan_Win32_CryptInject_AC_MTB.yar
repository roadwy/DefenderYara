
rule Trojan_Win32_CryptInject_AC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 cb 59 f7 db f7 d3 81 c3 90 02 04 29 d8 5b ff 20 90 00 } //01 00 
		$a_03_1 = {89 e9 81 c1 90 02 04 2b 31 89 e9 81 c1 90 02 04 31 31 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}