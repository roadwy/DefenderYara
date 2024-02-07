
rule Trojan_Win32_SpyBot_MR_MTB{
	meta:
		description = "Trojan:Win32/SpyBot.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 03 00 "
		
	strings :
		$a_02_0 = {29 f6 2b 37 f7 de 90 02 0a c1 ce 90 01 01 29 d6 83 ee 90 01 01 29 d2 29 f2 f7 da c1 c2 90 01 01 d1 ca 6a 90 01 01 8f 01 01 31 83 e9 90 01 01 83 eb 90 01 01 85 db 75 90 00 } //01 00 
		$a_00_1 = {70 00 6e 00 63 00 6f 00 62 00 6a 00 61 00 70 00 69 00 2e 00 64 00 6c 00 6c 00 } //01 00  pncobjapi.dll
		$a_00_2 = {70 00 69 00 2e 00 64 00 6c 00 6c 00 } //01 00  pi.dll
		$a_01_3 = {6e 64 64 65 61 70 69 2e 64 6c 6c } //00 00  nddeapi.dll
	condition:
		any of ($a_*)
 
}