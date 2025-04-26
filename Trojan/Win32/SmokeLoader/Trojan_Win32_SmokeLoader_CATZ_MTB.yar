
rule Trojan_Win32_SmokeLoader_CATZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CATZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 88 10 40 00 6a 00 ff ?? ?? ?? ?? ?? 6a 00 6a 00 8d 44 24 48 50 ff ?? ?? ?? ?? ?? 6a 00 8d 8c 24 44 08 00 00 51 ff 15 24 10 40 00 6a 00 ff 15 e4 10 40 00 6a 00 8d 94 24 44 18 00 00 52 68 a0 4b 40 00 ff 15 28 10 40 00 8d 84 24 40 10 00 00 50 6a 00 68 b8 4b 40 00 68 00 4c 40 00 ff 15 14 11 40 00 6a 00 ff 15 c8 10 40 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}