
rule Trojan_Win32_CryptInject_YAR_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c3 02 c3 32 c3 90 13 0f 1f 00 02 c3 8a ff 90 13 32 c3 8a c0 c0 c8 9b 90 13 90 90 aa 0f 1f 12 90 13 0f 1f 12 49 0f 1f 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}