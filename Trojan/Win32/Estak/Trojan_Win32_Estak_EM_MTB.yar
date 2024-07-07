
rule Trojan_Win32_Estak_EM_MTB{
	meta:
		description = "Trojan:Win32/Estak.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 ec 04 c7 04 24 10 14 40 00 c3 } //5
		$a_01_1 = {81 fb f4 01 00 00 75 05 bb 00 00 00 00 } //1
		$a_01_2 = {81 ff f4 01 00 00 75 05 bf 00 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}