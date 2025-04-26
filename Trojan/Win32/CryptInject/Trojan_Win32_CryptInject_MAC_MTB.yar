
rule Trojan_Win32_CryptInject_MAC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 cb c1 e1 04 03 4d ?? 8d 45 ec bf ?? ?? ?? ?? be 04 00 00 00 8a 11 30 10 41 40 4e 75 } //1
		$a_03_1 = {33 c0 8b f2 8a 54 05 ?? 30 14 0f 41 40 89 4d ?? 3b 4d 08 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}