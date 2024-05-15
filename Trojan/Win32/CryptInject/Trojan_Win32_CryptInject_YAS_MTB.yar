
rule Trojan_Win32_CryptInject_YAS_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f2 45 8b 85 80 fe ff ff 88 90 90 90 01 04 8b 8d 80 fe ff ff 83 c1 01 89 8d 80 fe ff ff 8b 95 90 00 } //01 00 
		$a_03_1 = {81 f1 89 00 00 00 8b 95 80 fe ff ff 88 8a 90 01 04 8b 85 80 fe ff ff 83 c0 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}