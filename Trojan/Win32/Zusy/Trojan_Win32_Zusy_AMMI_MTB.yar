
rule Trojan_Win32_Zusy_AMMI_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {be c3 07 79 b1 b1 ad 6e 83 8c b0 69 8c 9d 83 d2 ce 8c 7e 7e 50 ad 9f c8 83 69 7c b0 b1 50 b1 b1 d2 ce ad 9a 8c 69 89 c5 83 8c b0 79 6e d2 c7 69 } //1
		$a_01_1 = {6a 40 68 00 10 00 00 68 ac 04 00 00 6a 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}