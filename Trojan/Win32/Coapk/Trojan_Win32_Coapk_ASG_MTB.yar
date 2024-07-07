
rule Trojan_Win32_Coapk_ASG_MTB{
	meta:
		description = "Trojan:Win32/Coapk.ASG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 ce 21 c9 e8 90 02 04 81 e9 76 81 73 c2 31 02 21 f6 29 ce 42 46 89 c9 39 fa 90 00 } //1
		$a_01_1 = {09 d8 81 eb 5f 55 46 1b 31 0e 83 ec 04 c7 04 24 78 e9 02 6d 5b 46 81 c3 01 00 00 00 39 d6 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}