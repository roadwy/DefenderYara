
rule Trojan_Win32_SmokeLoader_GEN_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GEN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f0 8b ce c1 e1 90 01 01 89 44 24 90 01 01 89 4c 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b c6 c1 e8 90 01 01 03 c5 50 89 44 24 90 01 01 8d 44 24 90 01 01 8d 14 37 31 54 24 90 01 01 50 c7 05 90 01 04 19 36 6b ff 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}