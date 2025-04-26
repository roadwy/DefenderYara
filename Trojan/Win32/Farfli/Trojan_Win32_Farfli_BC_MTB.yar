
rule Trojan_Win32_Farfli_BC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 10 80 f2 15 80 c2 15 88 10 40 83 ee 01 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}