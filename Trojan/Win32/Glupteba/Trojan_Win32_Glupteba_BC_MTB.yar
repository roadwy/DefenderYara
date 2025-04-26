
rule Trojan_Win32_Glupteba_BC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 1a 81 c7 79 19 cb 16 81 c2 04 00 00 00 21 f9 41 39 f2 75 e6 } //1
		$a_01_1 = {01 d2 81 ea 01 00 00 00 81 c1 01 00 00 00 29 d6 81 f9 1f be 00 01 75 c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}