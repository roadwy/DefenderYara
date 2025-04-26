
rule Trojan_Win32_TrickBotCrypt_FM_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 03 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 03 ca 2b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca 2b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8b 55 0c 8b 75 08 8a 04 02 32 04 0e 8b 4d ec } //5
		$a_01_1 = {8b 55 0c 88 04 0a e9 } //5
		$a_81_2 = {4b 68 71 4e 74 5f 3e 67 64 77 6d 78 62 47 3c 4b 52 26 28 48 73 79 29 7a 76 33 65 72 41 4d 40 43 52 77 2b 6e 50 38 58 64 6d 4d 50 5e 54 30 4e 32 4d 36 42 5e 74 68 23 46 6d 77 5a 40 72 51 4f 40 26 52 52 66 4a 76 39 4d 65 32 4d 4d 42 6c 40 33 50 66 50 55 58 6e 26 61 70 68 2b 3e 4e 26 64 51 59 3f 63 61 40 6b 51 75 7a 75 28 4a 35 67 4d 57 49 31 48 40 } //10 KhqNt_>gdwmxbG<KR&(Hsy)zv3erAM@CRw+nP8XdmMP^T0N2M6B^th#FmwZ@rQO@&RRfJv9Me2MMBl@3PfPUXn&aph+>N&dQY?ca@kQuzu(J5gMWI1H@
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_81_2  & 1)*10) >=10
 
}