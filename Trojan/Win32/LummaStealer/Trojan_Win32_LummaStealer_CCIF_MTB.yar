
rule Trojan_Win32_LummaStealer_CCIF_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 c8 01 c0 89 c1 31 d1 f7 d0 21 d0 01 c0 29 c8 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}