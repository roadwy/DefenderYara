
rule Trojan_Win32_CryptInject_ERN_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.ERN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ff 8b 04 95 40 b7 41 00 8b c8 81 e1 ff 00 00 00 c1 e8 08 33 04 8d 40 bb 41 00 83 c2 01 81 fa 00 08 00 00 89 04 95 3c bb 41 00 72 d5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}