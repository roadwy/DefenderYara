
rule Trojan_Win32_CryptInject_SN_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 68 ?? ?? 00 00 6a 00 e8 ?? ?? ?? ?? 89 45 fc 33 c9 bb } //2
		$a_02_1 = {85 c9 76 33 8b c1 bf 05 00 00 00 33 d2 f7 f7 85 d2 75 ?? 8a 03 34 ?? 8b 55 fc 03 d1 73 05 e8 ?? ?? ?? ?? 88 02 eb 10 8b 45 fc 03 c1 73 05 e8 ?? ?? ?? ?? 8a 13 88 10 41 43 81 f9 ?? ?? 00 00 75 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=4
 
}