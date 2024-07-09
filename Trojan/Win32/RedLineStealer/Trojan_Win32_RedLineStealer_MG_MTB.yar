
rule Trojan_Win32_RedLineStealer_MG_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 85 ?? ?? ?? ?? c7 85 e4 3b f2 ff ?? ?? ?? ?? 8b 8d e4 3b f2 ff 83 c1 01 89 8d 60 3a f2 ff 8b 95 e4 3b f2 ff 8a 02 88 85 f7 3b f2 ff 83 85 e4 3b f2 ff 01 80 bd f7 3b f2 ff 00 75 ?? 8b 8d e4 3b f2 ff 2b 8d 60 3a f2 ff 89 8d fc 39 f2 ff 8b 95 a8 3b f2 ff 3b 95 fc 39 f2 ff 73 ?? 8b 85 a8 3b f2 ff 0f be 88 } //1
		$a_03_1 = {85 c0 74 34 b9 4d 5a 00 00 66 39 08 75 2a 8b 48 3c 03 c8 81 39 ?? ?? ?? ?? 75 ?? b8 ?? ?? ?? ?? 66 39 41 18 75 ?? 83 79 74 0e 76 0c 83 b9 ?? ?? ?? ?? 00 74 ?? b0 01 c3 32 c0 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}