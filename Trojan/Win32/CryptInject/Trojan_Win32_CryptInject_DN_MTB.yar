
rule Trojan_Win32_CryptInject_DN_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 33 bf 8d 00 00 00 89 f5 89 ef 89 3b 4b 83 c3 05 42 48 0f 85 } //01 00 
		$a_01_1 = {31 fe 89 f7 89 e7 f7 d5 4d 75 ec } //00 00 
	condition:
		any of ($a_*)
 
}