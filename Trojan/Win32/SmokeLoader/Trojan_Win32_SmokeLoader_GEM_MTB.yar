
rule Trojan_Win32_SmokeLoader_GEM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 45 90 01 01 8d 0c 37 31 4d 90 01 01 50 89 45 90 01 01 8d 45 90 01 01 50 c7 05 90 01 04 19 36 6b ff e8 90 01 04 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 81 c7 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}