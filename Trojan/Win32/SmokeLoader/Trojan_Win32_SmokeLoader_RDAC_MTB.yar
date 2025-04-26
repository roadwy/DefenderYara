
rule Trojan_Win32_SmokeLoader_RDAC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 95 dc f3 ff ff 8b 85 d8 f3 ff ff 8b 75 0c 30 14 38 83 fe 0f 75 5b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}