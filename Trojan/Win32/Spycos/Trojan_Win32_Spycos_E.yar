
rule Trojan_Win32_Spycos_E{
	meta:
		description = "Trojan:Win32/Spycos.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 6d 6f 64 67 75 61 72 64 2e 70 61 73 } //1 \modguard.pas
		$a_03_1 = {8b 00 8b 10 ff 52 38 eb 05 e8 ?? ?? ?? ?? 5b e8 } //1
		$a_01_2 = {8b 45 f4 89 45 f0 8b 5d f0 85 db 74 05 83 eb 04 8b 1b 43 53 8d 55 ec a1 } //1
		$a_03_3 = {75 34 8d 55 ?? b8 ?? ?? 41 00 e8 ?? ?? ff ff 8b 45 ?? 50 8d 55 ?? b8 ?? ?? 41 00 e8 ?? ?? ff ff 8b 45 ?? 8d 4d ?? 5a e8 ?? ?? ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}