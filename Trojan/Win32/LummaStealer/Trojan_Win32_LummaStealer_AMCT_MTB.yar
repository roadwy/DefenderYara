
rule Trojan_Win32_LummaStealer_AMCT_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.AMCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c9 85 c0 0f 94 c1 8b 0c 8d ?? ?? ?? ?? [0-28] ff ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 08 a3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}