
rule Trojan_Win32_Remcos_NR_MTB{
	meta:
		description = "Trojan:Win32/Remcos.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {46 4d 41 39 33 3f 83 c4 04 58 50 53 83 c4 04 81 e8 bf ee 00 00 58 69 8d } //3
		$a_01_1 = {3a 48 3c 5e 50 51 83 c4 04 e8 0b 00 00 00 00 33 3c 3d 50 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}