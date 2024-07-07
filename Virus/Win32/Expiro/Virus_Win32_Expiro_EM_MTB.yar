
rule Virus_Win32_Expiro_EM_MTB{
	meta:
		description = "Virus:Win32/Expiro.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 51 52 53 55 56 57 e8 00 00 00 00 } //2
		$a_01_1 = {81 c6 00 04 00 00 81 c0 00 04 00 00 81 fe 00 c0 08 00 0f 85 } //3
		$a_01_2 = {81 c6 00 04 00 00 81 c1 00 04 00 00 81 fe 00 c0 08 00 0f 85 } //3
		$a_01_3 = {81 c7 00 04 00 00 81 c2 00 04 00 00 81 ff 00 c0 08 00 0f 85 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=5
 
}