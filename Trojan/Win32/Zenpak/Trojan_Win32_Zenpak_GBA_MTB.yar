
rule Trojan_Win32_Zenpak_GBA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e0 50 8f 05 ?? ?? ?? ?? 4a b9 ?? ?? ?? ?? e2 1c 48 89 2d ?? ?? ?? ?? 89 d0 31 d0 01 d0 4a 8d 05 ?? ?? ?? ?? 31 18 e9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}