
rule Trojan_Win32_LummaStealer_ALM_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ALM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 d3 80 c3 60 32 1c 14 80 c3 20 88 1c 14 42 83 fa 04 } //3
		$a_01_1 = {89 d3 80 c3 9d 32 1c 10 80 c3 ef 88 1c 10 42 81 0e 04 eb 7a e0 00 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}