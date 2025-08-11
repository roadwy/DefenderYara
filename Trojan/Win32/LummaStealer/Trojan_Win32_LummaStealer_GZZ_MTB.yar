
rule Trojan_Win32_LummaStealer_GZZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 04 ?? ?? ?? ?? 31 c1 89 4c 24 ?? 8b 4c 24 ?? 89 ca 83 f2 ?? 83 e1 ?? 8d 0c 4a fe c1 88 8c 04 ?? ?? ?? ?? 40 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}