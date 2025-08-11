
rule Trojan_Win32_Guloader_GPB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {68 75 6c 65 66 6f 72 73 6b 65 72 6e 65 73 20 70 72 65 65 73 73 65 6e 74 69 61 6c 6c 79 } //1 huleforskernes preessentially
		$a_81_1 = {6c 69 67 6b 69 73 74 65 6d 61 67 61 73 69 6e 65 74 20 67 69 70 73 64 65 70 6f 6e 65 72 69 6e 67 73 70 6c 61 64 73 65 72 73 } //1 ligkistemagasinet gipsdeponeringspladsers
		$a_81_2 = {68 75 72 6c 77 69 6e 64 } //1 hurlwind
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}