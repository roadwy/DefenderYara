
rule Trojan_Win32_LummaStealer_GZK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 ?? 8a 1c 10 8a c3 32 c1 32 44 24 ?? 88 04 39 83 f9 ?? ?? ?? 8d 41 ?? c0 e3 ?? 83 e0 ?? 8a 04 10 c0 e8 ?? 32 c3 32 c1 88 04 29 41 81 f9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}