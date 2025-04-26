
rule Trojan_Win32_BlackMoon_GNT_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {2a 43 5d 44 0a 53 ?? 67 00 25 3c 0b 83 37 ?? 59 b0 00 8c 1c c7 36 b7 92 04 68 01 27 } //10
		$a_01_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 45 6e 63 72 79 70 74 53 79 6e 61 70 74 69 63 73 2e 63 6f 6d } //1 C:\Windows\EncryptSynaptics.com
		$a_01_2 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } //1 BlackMoon RunTime Error
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}
rule Trojan_Win32_BlackMoon_GNT_MTB_2{
	meta:
		description = "Trojan:Win32/BlackMoon.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {f3 22 ec 14 ae 89 0a 33 72 63 85 b2 ?? ?? ?? ?? 82 70 67 e4 11 65 a6 } //5
		$a_03_1 = {13 38 44 7d ?? 13 38 8d be ?? ?? ?? ?? 78 ?? 13 38 8c 40 c7 13 38 32 f0 5f 10 38 } //5
		$a_01_2 = {32 d8 80 f5 b9 66 0f bd c8 8b 4c 25 00 8d ad 04 00 00 00 66 3b fc 89 0c 04 66 2b c2 66 0f ab c8 } //5
		$a_01_3 = {68 6c 4d 65 6d 68 72 74 75 61 68 74 65 56 69 68 6c 6f 63 61 68 5a 77 41 6c } //1 hlMemhrtuahteVihlocahZwAl
		$a_01_4 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 } //1 BlackMoon RunTime Error
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}