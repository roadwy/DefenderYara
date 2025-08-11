
rule Trojan_Win32_LummaStealer_DT_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 c9 0f 49 d1 81 e2 ?? ?? ?? ?? 89 c8 29 d0 0f b6 d3 8d 14 52 8b bc 24 ?? ?? ?? ?? 32 04 0f 30 d0 88 04 0f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}