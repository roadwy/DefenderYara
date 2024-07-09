
rule Trojan_Win32_SmokeLoader_GBS_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 8b c7 c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 8b 45 ?? 01 45 ?? 8b c7 c1 e0 04 03 45 ?? 8d 0c 3e 33 c1 33 45 ?? 50 8d 45 ?? 50 e8 ?? ?? ?? ?? 83 65 ?? ?? 8b 45 ?? 01 45 ?? 2b 75 ?? ff 4d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}