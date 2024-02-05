
rule Trojan_Win32_CryptInject_DY_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 04 0a 34 44 04 19 88 01 41 4e 75 } //00 00 
	condition:
		any of ($a_*)
 
}