
rule Trojan_Win32_RopProof_RPX_MTB{
	meta:
		description = "Trojan:Win32/RopProof.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 6f 73 65 72 31 32 } //1 ioser12
		$a_01_1 = {4a 61 76 61 5f 63 6f 6d 5f 73 75 6e 5f 63 6f 72 62 61 5f 73 65 } //1 Java_com_sun_corba_se
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_RopProof_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/RopProof.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {98 5b f1 e9 4b 1d 61 4e 4b da fc a7 6b f9 23 4f 3e 6a 59 fd 73 70 05 df 76 61 24 18 e6 ab 09 7d 0d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}