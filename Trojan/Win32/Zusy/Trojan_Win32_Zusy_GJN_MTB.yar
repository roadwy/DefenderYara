
rule Trojan_Win32_Zusy_GJN_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 89 6c 24 10 8d 6c 24 10 29 c4 53 56 57 a1 2c b1 40 00 31 45 fc } //10
		$a_01_1 = {2e 72 6f 70 66 } //1 .ropf
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}