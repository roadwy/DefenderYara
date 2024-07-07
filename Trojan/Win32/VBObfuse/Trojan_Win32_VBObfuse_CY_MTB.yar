
rule Trojan_Win32_VBObfuse_CY_MTB{
	meta:
		description = "Trojan:Win32/VBObfuse.CY!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 19 81 fa 3f ab 31 be 75 08 } //1
		$a_01_1 = {31 f3 81 fb 80 93 ac 9d 75 08 } //1
		$a_01_2 = {01 1c 10 81 fa 39 5f 87 8b 75 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}