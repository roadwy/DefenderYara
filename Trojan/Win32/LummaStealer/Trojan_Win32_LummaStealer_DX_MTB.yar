
rule Trojan_Win32_LummaStealer_DX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 c1 ea 1e f7 d0 89 d6 09 c6 21 d0 8d 14 36 f7 d2 01 f2 09 c2 69 c2 ?? ?? ?? ?? 01 c8 48 8b 15 ?? ?? ?? ?? 89 04 8a 41 81 f9 ?? ?? ?? ?? 75 cf } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}