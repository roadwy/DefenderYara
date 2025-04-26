
rule Trojan_Win32_CryptInject_LM_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 8b 15 30 00 00 00 90 13 50 8f 42 08 90 13 8b 5d 0c 03 5b 3c 90 13 64 a1 30 00 00 00 8b 40 0c 90 13 8d 40 0c 8b 00 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}