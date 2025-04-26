
rule Trojan_Win32_SmokeLoader_ASGE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ASGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c0 64 89 45 ?? 83 6d ?? 64 8b 45 bc 8a 4d ?? 03 c6 30 08 83 fb 0f 75 } //4
		$a_01_1 = {6c 6f 70 65 79 65 76 65 63 61 76 69 6e 6f 78 69 67 69 6c 61 6b 65 74 65 74 } //1 lopeyevecavinoxigilaketet
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}