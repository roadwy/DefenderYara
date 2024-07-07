
rule Trojan_Win32_Amadey_ER_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 06 8d 4e 01 8b 7d e8 83 c6 02 8a } //3
		$a_01_1 = {0f b6 01 8b 4d e4 c0 e2 04 0a } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}