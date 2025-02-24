
rule Trojan_Win32_LummaStealer_GQX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GQX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 f9 09 f0 09 cb 31 d8 89 d1 21 c1 31 c2 09 d1 89 4d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}