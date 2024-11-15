
rule Trojan_Win32_CryptInject_CDD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d2 0f b6 5c 96 04 8d 54 96 04 89 95 ?? ?? fe ff 8b 95 ?? ?? fe ff 30 5c 3a ff 8b 95 ?? ?? fe ff 8b 1a 8b 95 ?? ?? fe ff 31 1a 8b 5c 86 04 03 9d ?? ?? fe ff 8b 95 ?? ?? fe ff 31 1a 3b 7d 10 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}