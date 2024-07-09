
rule Trojan_Win32_SmokeLoader_GI_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 05 03 45 e0 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ec 8b 45 f8 31 45 0c 8b 45 ec 31 45 0c 8b 45 0c 29 45 fc 89 75 f4 8b 45 d0 01 45 f4 2b 7d f4 ff 4d e4 8b 4d fc 89 7d e8 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}