
rule Trojan_Win64_Autorun_MP_MTB{
	meta:
		description = "Trojan:Win64/Autorun.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 06 83 f8 01 0f 84 4c 01 00 00 85 ff 0f 84 65 01 00 00 48 8b 05 51 27 1c 00 48 8b 00 48 85 c0 74 0c 45 31 c0 ba 02 00 00 00 31 c9 } //1
		$a_01_1 = {75 e3 48 8b 35 8c 28 1c 00 31 ff 8b 06 83 f8 01 0f 84 56 01 00 00 8b 06 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}