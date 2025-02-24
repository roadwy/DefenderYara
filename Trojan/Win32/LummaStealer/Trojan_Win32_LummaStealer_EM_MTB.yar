
rule Trojan_Win32_LummaStealer_EM_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 e7 01 f8 8d 4e ff 42 83 fe 01 89 ce 77 d5 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_Win32_LummaStealer_EM_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b d8 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 ba } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}