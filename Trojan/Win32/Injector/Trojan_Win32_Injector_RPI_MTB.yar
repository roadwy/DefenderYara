
rule Trojan_Win32_Injector_RPI_MTB{
	meta:
		description = "Trojan:Win32/Injector.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 3e 29 c1 48 81 c6 04 00 00 00 [0-10] 39 de 75 e4 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}