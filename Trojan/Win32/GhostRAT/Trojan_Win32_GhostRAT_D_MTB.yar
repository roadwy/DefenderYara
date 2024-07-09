
rule Trojan_Win32_GhostRAT_D_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 08 81 e9 ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 88 0a 8b 45 ?? 03 45 ?? 0f be 08 83 f1 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}