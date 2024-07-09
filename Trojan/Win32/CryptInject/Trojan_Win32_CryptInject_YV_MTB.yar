
rule Trojan_Win32_CryptInject_YV_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 8b ?? ?? 25 ff 00 00 00 0f b6 c8 51 e8 ?? ?? ?? ?? 83 c4 04 8b 45 08 8b 55 0c b1 ?? e8 ?? ?? ?? ?? 25 ff 00 00 00 0f b6 d0 52 } //1
		$a_02_1 = {55 8b ec a1 ?? ?? ?? 00 c1 e8 ?? 25 ff ff ff 00 0f b6 4d 08 33 ?? ?? ?? ?? 00 81 e1 ff 00 00 00 33 04 ?? ?? ?? ?? 00 a3 ?? ?? ?? 00 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}