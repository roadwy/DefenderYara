
rule Trojan_Win32_SmokeLoader_EABZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.EABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c0 46 89 44 24 0c 83 6c 24 0c 0a 90 90 83 6c 24 0c 3c 8a 44 24 0c 30 04 3b 83 fd 0f } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}