
rule Trojan_Win32_LummaStealer_ZZF_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZZF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5e 38 d3 d9 03 d9 14 42 28 a8 f4 7b 00 77 b9 ae 50 60 fa 16 46 74 62 9d f5 ce d3 15 a8 c9 4c af 11 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}