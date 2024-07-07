
rule Trojan_Win32_SmokeLoader_UNI_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.UNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}