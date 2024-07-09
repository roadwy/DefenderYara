
rule Trojan_Win32_SmokeLoader_NEAD_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b f0 89 44 24 ?? 8b c6 c1 e0 ?? 89 44 24 10 8b 44 24 28 01 44 24 10 8b 44 24 18 8b d6 c1 ea ?? 03 d5 03 c6 31 44 24 } //10
		$a_01_1 = {b5 02 8a 94 31 d6 38 00 00 88 14 30 81 c4 18 0c 00 00 c3 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}