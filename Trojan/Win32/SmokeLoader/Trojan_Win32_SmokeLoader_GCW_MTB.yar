
rule Trojan_Win32_SmokeLoader_GCW_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 ?? 03 45 ?? 8d 0c 3b 33 c1 31 45 ?? 2b 75 ?? 81 c3 ?? ?? ?? ?? ff 4d ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}