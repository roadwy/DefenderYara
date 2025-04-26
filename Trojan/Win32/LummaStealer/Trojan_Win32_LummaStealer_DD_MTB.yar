
rule Trojan_Win32_LummaStealer_DD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 04 ?? ?? ?? ?? 89 c2 21 ca 01 d2 29 d1 01 c1 89 ca f7 d2 81 e2 ed 00 00 00 83 e1 12 29 d1 fe c1 88 8c 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}