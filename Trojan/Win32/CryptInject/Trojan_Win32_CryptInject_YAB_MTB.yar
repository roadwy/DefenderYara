
rule Trojan_Win32_CryptInject_YAB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 e8 90 02 20 4b 75 90 01 01 e8 90 01 03 ff 90 02 20 90 05 0a 01 90 85 90 02 10 90 05 0a 01 90 8b c8 03 cb 90 05 0a 01 90 c6 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}