
rule Trojan_Win32_SmokeLoader_PAEH_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PAEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 44 24 10 2b d8 89 44 24 14 8b c3 c1 e0 04 89 44 24 10 8b 44 24 28 01 44 24 10 8b c3 c1 e8 05 89 44 24 14 8b 44 24 2c 01 44 24 14 8d 04 2b 33 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 18 8d ad ?? ?? ?? ?? 4e 0f 85 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}