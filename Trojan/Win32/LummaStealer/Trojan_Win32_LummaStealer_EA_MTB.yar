
rule Trojan_Win32_LummaStealer_EA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 ce 83 e6 06 89 d3 81 f3 8b 00 00 00 01 f3 32 1c 14 80 c3 49 88 1c 14 42 83 c1 02 83 fa 05 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}