
rule Trojan_Win32_RisePro_LZ_MTB{
	meta:
		description = "Trojan:Win32/RisePro.LZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 50 06 00 00 10 00 00 00 ae 03 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 38 83 00 00 00 60 06 00 00 3c 00 00 00 be 03 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}