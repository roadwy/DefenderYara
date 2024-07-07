
rule Trojan_Win32_Guloader_SSD_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 72 67 65 6e 66 72 75 65 72 6e 65 73 2e 74 65 67 } //1 morgenfruernes.teg
		$a_01_1 = {68 6d 6e 69 6e 67 73 6c 73 65 2e 63 6f 77 } //1 hmningslse.cow
		$a_01_2 = {53 6b 61 74 74 65 62 65 72 65 67 6e 69 6e 67 73 2e 45 66 66 } //1 Skatteberegnings.Eff
		$a_01_3 = {62 68 64 48 5f 65 61 } //1 bhdH_ea
		$a_01_4 = {71 75 70 42 6d 71 6d } //1 qupBmqm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}