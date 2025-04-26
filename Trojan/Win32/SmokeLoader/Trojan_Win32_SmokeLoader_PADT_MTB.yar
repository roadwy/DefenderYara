
rule Trojan_Win32_SmokeLoader_PADT_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 0f b7 0d ?? ?? ?? ?? 81 e1 ff 7f 00 00 89 0a c3 } //1
		$a_01_1 = {8b 44 24 18 83 c0 64 89 44 24 10 83 6c 24 10 64 8a 4c 24 10 8b 44 24 14 30 0c 30 83 bc 24 5c 08 00 00 0f 75 5f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}