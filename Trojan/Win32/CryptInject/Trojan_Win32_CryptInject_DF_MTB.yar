
rule Trojan_Win32_CryptInject_DF_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 c1 8a 0f 03 4d f4 81 e1 ff 00 00 00 8a 0c 19 30 08 } //02 00 
		$a_01_1 = {8a 14 18 03 c3 88 17 89 4d f4 88 08 } //00 00 
	condition:
		any of ($a_*)
 
}