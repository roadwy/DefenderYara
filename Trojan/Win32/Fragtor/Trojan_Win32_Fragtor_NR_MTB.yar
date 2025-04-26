
rule Trojan_Win32_Fragtor_NR_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a d9 88 5d e7 ff 75 dc e8 a5 05 00 00 59 e8 30 07 00 00 8b f0 33 ff 39 3e } //3
		$a_01_1 = {eb 05 8a d9 88 5d e7 ff 75 dc e8 a5 05 00 00 59 e8 30 07 00 00 8b f0 33 ff 39 3e 74 1b 56 e8 fd 04 00 00 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}