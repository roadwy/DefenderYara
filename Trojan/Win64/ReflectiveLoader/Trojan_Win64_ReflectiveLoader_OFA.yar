
rule Trojan_Win64_ReflectiveLoader_OFA{
	meta:
		description = "Trojan:Win64/ReflectiveLoader.OFA,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {5b bc 4a 6a } //1
		$a_01_1 = {5d 68 fa 3c } //1
		$a_01_2 = {8e 4e 0e ec } //1
		$a_01_3 = {aa fc 0d 7c } //1
		$a_01_4 = {54 ca af 91 } //1
		$a_01_5 = {b8 0a 4c 53 } //1
		$a_81_6 = {52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 } //10 ReflectiveLoader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_81_6  & 1)*10) >=16
 
}