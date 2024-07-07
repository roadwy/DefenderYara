
rule Trojan_Win32_CryptInject_YQ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e8 f1 a0 fa ff 90 90 83 90 01 06 76 90 01 01 90 05 0a 01 90 b8 90 01 04 e8 90 01 04 8b f0 90 05 0a 01 90 33 c0 a3 90 01 03 00 90 05 0a 01 90 33 c0 a3 90 01 03 00 90 90 c6 90 01 06 33 c0 89 03 b8 90 01 03 00 8b d6 03 13 8a 90 01 04 00 32 08 88 0a ff 03 40 81 90 01 08 8b c6 83 c0 90 01 01 89 03 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}