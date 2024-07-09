
rule Trojan_Win32_Rozena_XI_MTB{
	meta:
		description = "Trojan:Win32/Rozena.XI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f0 f7 e5 d1 ea 83 e2 ?? 8d 04 52 89 f2 29 c2 0f b6 92 ?? ?? ?? ?? 30 14 37 f7 d8 0f b6 84 06 ?? ?? ?? ?? 30 44 37 ?? 83 c6 ?? 39 f3 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}