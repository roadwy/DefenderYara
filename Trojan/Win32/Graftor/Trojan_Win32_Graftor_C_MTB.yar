
rule Trojan_Win32_Graftor_C_MTB{
	meta:
		description = "Trojan:Win32/Graftor.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d2 d3 f1 c0 c1 ?? 33 da 03 ea 0a c9 8b 84 31 ?? ?? ?? ?? 8d b4 0e ?? ?? ?? ?? c1 e9 ?? 0f b7 d1 87 4c ?? ?? 33 c3 d3 f2 0f 99 c2 0f c8 40 35 ?? ?? ?? ?? 66 03 ca c1 c8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}