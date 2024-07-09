
rule Trojan_Win32_BazzarLoader_KM_MTB{
	meta:
		description = "Trojan:Win32/BazzarLoader.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {46 75 63 6b 20 44 65 66 } //1 Fuck Def
		$a_00_1 = {74 58 67 3e 3e 6f 73 69 78 44 55 53 54 6b 38 } //1 tXg>>osixDUSTk8
		$a_02_2 = {c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 8d 45 ?? 89 5d ?? 50 53 ff 75 ?? 6a 4c 68 ?? ?? ?? ?? ff 75 ?? e8 ?? ?? ?? ?? 85 c0 5f 74 ?? 8b 45 ?? ff 30 50 ff 75 ?? 53 6a 01 53 ff 75 ?? e8 ?? ?? ?? ?? 85 c0 0f 95 c0 eb } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}