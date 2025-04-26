
rule Trojan_Win32_PSWStealer_DA_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 31 72 65 63 74 6f 72 79 5f 33 33 32 32 5f 74 } //5 d1rectory_3322_t
	condition:
		((#a_01_0  & 1)*5) >=5
 
}