
rule Trojan_O97M_Schla_A_MTB{
	meta:
		description = "Trojan:O97M/Schla.A!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 68 65 64 75 6c 65 2e 53 65 72 76 69 63 65 22 29 } //2 = CreateObject("Schedule.Service")
		$a_01_1 = {43 61 6c 6c 42 79 4e 61 6d 65 } //2 CallByName
		$a_03_2 = {2e 54 61 67 90 09 10 00 3d 20 [0-10] 2e 54 61 67 } //1
		$a_03_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 [0-10] 2e 4c 61 62 65 6c [0-02] 2e 54 61 67 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}