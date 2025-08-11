
rule Trojan_Win32_LummaStealer_PGA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a c1 c0 e8 04 32 04 16 32 c1 8b 4d ?? 32 45 ?? 88 04 16 8b 45 ?? 40 89 4d f8 89 45 ?? 3b cb 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}