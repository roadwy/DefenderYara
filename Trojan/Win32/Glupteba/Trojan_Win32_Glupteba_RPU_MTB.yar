
rule Trojan_Win32_Glupteba_RPU_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.RPU!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 11 4e 81 c1 01 00 00 00 39 d9 75 e9 } //1
		$a_01_1 = {8d 14 10 8b 12 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}