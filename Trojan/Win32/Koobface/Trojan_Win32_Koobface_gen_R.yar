
rule Trojan_Win32_Koobface_gen_R{
	meta:
		description = "Trojan:Win32/Koobface.gen!R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 7c 56 89 02 e8 } //1
		$a_01_1 = {3f 61 63 74 69 6f 6e 3d 67 6f 6f 67 67 65 6e } //1 ?action=googgen
		$a_01_2 = {74 68 65 67 6f 6f 67 2e 74 6d 70 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}