
rule Trojan_Win32_SmokeLoader_GED_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 45 ?? 8d 0c 37 89 45 ?? 33 c1 31 45 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 8b 45 ?? 29 45 ?? 8b 45 ?? 81 c7 ?? ?? ?? ?? ff 4d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}