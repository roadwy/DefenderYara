
rule Trojan_Win32_LummaStealer_YR_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.YR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c0 29 c0 0f c8 8d 05 00 20 40 00 83 c0 02 50 11 c0 8d 80 42 44 23 0b 58 ff e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}