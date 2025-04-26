
rule Trojan_Win32_LummaStealer_MK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 f0 8b f3 f6 2f 47 e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}