
rule Trojan_Win32_SmokeLoader_BP_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e0 8b 4d ec 03 45 d4 89 45 f4 8b 45 fc 03 c6 89 45 f0 8b c6 d3 e8 03 45 d0 89 45 f8 8b 45 f0 31 45 f4 8b 45 f4 33 45 f8 89 1d [0-04] 29 45 e4 89 45 f4 8b 45 cc 29 45 fc ff 4d e0 0f 85 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}