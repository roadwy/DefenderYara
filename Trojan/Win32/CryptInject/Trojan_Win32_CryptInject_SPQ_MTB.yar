
rule Trojan_Win32_CryptInject_SPQ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8a 18 32 d9 80 f3 80 88 18 40 38 10 75 f2 } //00 00 
	condition:
		any of ($a_*)
 
}