
rule Trojan_Win32_CryptInject_YK_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {26 05 8d 0c 30 8a 41 03 8a d0 8a d8 80 e2 f0 80 e3 fc c0 e2 02 0a 11 c0 e0 06 0a 41 02 c0 e3 04 0a 59 01 8b 4d f4 88 14 0f 47 88 1c 0f 47 89 7d f8 88 04 0f 8d 7d f8 e8 44 ff ff ff 03 75 fc 8b 7d f8 3b 35 ?? ?? 28 05 72 b3 } //1
		$a_02_1 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 [0-14] 42 00 c6 05 ?? ?? ?? 05 6b c6 05 ?? ?? ?? 05 6c c6 05 ?? ?? ?? 05 33 c6 05 ?? ?? ?? 05 6e c6 05 ?? ?? ?? 05 65 c6 05 ?? ?? ?? 05 32 c6 05 ?? ?? ?? 05 6c c6 05 ?? ?? ?? 05 65 c6 05 ?? ?? ?? 05 64 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}