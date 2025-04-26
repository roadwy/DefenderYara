
rule Trojan_Win32_Fauppod_GZT_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 42 8d 05 ?? ?? ?? ?? 31 20 89 d0 83 f0 ?? e8 ?? ?? ?? ?? c3 48 4a 01 d0 29 c2 89 35 ?? ?? ?? ?? 4a 42 40 89 2d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}