
rule Trojan_Win32_Zusy_NEAA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 82 fc ad 90 01 01 00 32 c1 41 88 84 15 a0 fb ff ff 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 42 83 fa 1b 7c da 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}