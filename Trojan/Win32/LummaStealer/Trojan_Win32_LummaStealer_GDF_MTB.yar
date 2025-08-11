
rule Trojan_Win32_LummaStealer_GDF_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d1 f7 d1 89 c6 21 ce 89 c7 31 d7 89 c1 01 f9 29 f1 21 d0 f7 d0 89 ca 31 c2 f7 d2 09 c1 21 d1 89 0c 24 8b 04 24 2d } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}