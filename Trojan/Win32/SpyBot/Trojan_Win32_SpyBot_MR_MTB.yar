
rule Trojan_Win32_SpyBot_MR_MTB{
	meta:
		description = "Trojan:Win32/SpyBot.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {29 f6 2b 37 f7 de [0-0a] c1 ce ?? 29 d6 83 ee ?? 29 d2 29 f2 f7 da c1 c2 ?? d1 ca 6a ?? 8f 01 01 31 83 e9 ?? 83 eb ?? 85 db 75 } //3
		$a_00_1 = {70 00 6e 00 63 00 6f 00 62 00 6a 00 61 00 70 00 69 00 2e 00 64 00 6c 00 6c 00 } //1 pncobjapi.dll
		$a_00_2 = {70 00 69 00 2e 00 64 00 6c 00 6c 00 } //1 pi.dll
		$a_01_3 = {6e 64 64 65 61 70 69 2e 64 6c 6c } //1 nddeapi.dll
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}