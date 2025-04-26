
rule Trojan_Win32_CryptInject_BSDK_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.BSDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 50 04 88 53 04 83 fe 04 0f 84 9d fe ff ff 0f b6 50 05 88 53 05 83 fe 05 0f 84 8d fe ff ff 0f b6 50 06 88 53 06 83 fe 06 0f 84 7d fe ff ff 0f b6 50 07 88 53 07 } //1
		$a_01_1 = {55 89 e5 50 64 a1 30 00 00 00 89 45 fc 8b 45 fc 83 c4 04 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}