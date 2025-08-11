
rule Trojan_Win32_LummaStealer_ZAK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZAK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 7c 24 24 10 8b 44 24 10 73 04 8d 44 24 10 8b 54 24 20 6a 00 8d 4c 24 10 51 52 50 a1 68 ad 58 00 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}