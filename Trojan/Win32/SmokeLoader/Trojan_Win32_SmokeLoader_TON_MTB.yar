
rule Trojan_Win32_SmokeLoader_TON_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.TON!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c2 89 45 90 01 01 8b c2 d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 4d 90 01 01 8b c2 90 00 } //1
		$a_03_1 = {d3 e8 89 35 90 01 04 03 45 90 01 01 89 45 fc 33 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 ff 4d 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}