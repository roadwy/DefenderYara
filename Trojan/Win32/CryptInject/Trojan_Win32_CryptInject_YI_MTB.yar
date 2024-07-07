
rule Trojan_Win32_CryptInject_YI_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {a1 fc 4b 46 00 50 e8 90 01 03 ff 90 05 0a 01 90 33 90 01 01 a3 90 01 03 00 90 05 0a 01 90 33 90 01 01 90 05 0a 01 90 33 90 01 08 90 05 0a 01 90 a1 90 01 0a 73 90 01 01 e8 90 01 03 ff 90 05 0a 01 90 a3 90 01 03 00 90 05 0a 01 90 8a 90 01 01 34 90 01 01 a2 90 01 03 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}