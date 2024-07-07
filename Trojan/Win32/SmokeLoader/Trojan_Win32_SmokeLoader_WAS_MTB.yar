
rule Trojan_Win32_SmokeLoader_WAS_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.WAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 ff 75 90 01 01 03 f3 33 75 90 01 01 8d 45 90 01 01 50 89 75 90 01 01 e8 90 01 04 ff 75 90 01 01 8d 45 90 01 01 50 e8 90 01 04 81 45 f8 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}