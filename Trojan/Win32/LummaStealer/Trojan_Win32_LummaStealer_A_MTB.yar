
rule Trojan_Win32_LummaStealer_A_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 07 25 80 2f 90 01 01 8b 90 01 11 f6 2f 47 e2 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}