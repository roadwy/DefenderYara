
rule Trojan_Win32_SmokeLoader_CREX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CREX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 31 44 24 10 8b 4c 24 10 8b 54 24 28 51 52 8d 44 24 18 50 e8 ?? ?? ?? ?? 8b 44 24 10 29 44 24 14 8d 44 24 2c } //1
		$a_01_1 = {c7 04 24 00 00 00 00 8b 44 24 48 89 04 24 8b 44 24 44 31 04 24 8b 04 24 8b 4c 24 40 89 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}