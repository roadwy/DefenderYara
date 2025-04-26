
rule Trojan_Win32_Kelios_CCJU_MTB{
	meta:
		description = "Trojan:Win32/Kelios.CCJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 9c bb 83 b3 8b 2c e8 be 70 fd ff 8b ca d3 f1 89 84 17 a9 9f c0 e0 ff e6 } //2
		$a_01_1 = {b5 ad 08 77 78 36 97 32 82 ba 8a 5c 9d b1 45 89 23 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}