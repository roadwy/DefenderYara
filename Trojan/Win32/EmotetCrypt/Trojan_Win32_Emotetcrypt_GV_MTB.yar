
rule Trojan_Win32_Emotetcrypt_GV_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 1a 03 c2 99 bd ?? ?? ?? ?? f7 fd a1 ?? ?? ?? ?? bd ?? ?? ?? ?? 2b e8 0f af e8 b8 ?? ?? ?? ?? 2b c1 0f af c1 b9 ?? ?? ?? ?? 2b ce 0f af 0d ?? ?? ?? ?? 03 d5 03 d0 8b 44 24 ?? 03 d1 8b 4c 24 ?? 2b d6 03 d7 8a 14 1a 30 10 } //1
		$a_81_1 = {52 64 70 39 4c 4b 45 44 4e 71 64 43 34 58 39 4b 50 79 4f 78 44 52 41 6c 3c 41 2a 4a 3e 61 5e 21 64 74 4e 65 7a 3f 50 6c 58 29 36 66 28 55 47 48 54 3f 5e 4f 33 3e 56 26 6d 38 39 57 63 3c 39 2a 33 2b 74 52 64 70 } //1 Rdp9LKEDNqdC4X9KPyOxDRAl<A*J>a^!dtNez?PlX)6f(UGHT?^O3>V&m89Wc<9*3+tRdp
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}