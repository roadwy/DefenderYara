
rule Trojan_Win32_LummaStealer_CCIZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 57 56 83 e4 ?? 83 ec ?? 89 e6 a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}