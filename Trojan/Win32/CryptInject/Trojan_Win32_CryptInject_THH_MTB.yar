
rule Trojan_Win32_CryptInject_THH_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.THH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 5d dc 8b 75 e4 8a 44 1e ff 84 c0 74 ?? 30 04 1e eb ?? c7 45 fc 08 00 00 00 e8 ?? ?? ?? ?? c7 45 fc ff ff ff ff eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}