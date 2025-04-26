
rule Trojan_Win32_CryptInject_YAS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 f2 45 8b 85 80 fe ff ff 88 90 90 ?? ?? ?? ?? 8b 8d 80 fe ff ff 83 c1 01 89 8d 80 fe ff ff 8b 95 } //1
		$a_03_1 = {81 f1 89 00 00 00 8b 95 80 fe ff ff 88 8a ?? ?? ?? ?? 8b 85 80 fe ff ff 83 c0 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}