
rule Trojan_Win32_LummaStealer_CI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c8 89 c1 83 e1 ?? 83 f1 ?? 25 ?? 00 00 00 29 c8 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 } //2
		$a_03_1 = {f7 da 8d 84 10 ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 30 c8 04 ?? 8b 4c 24 ?? 8b 14 24 88 04 11 8b 04 24 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}