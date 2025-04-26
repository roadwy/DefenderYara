
rule Trojan_Win32_Zenpak_GMQ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 68 69 6e 67 64 69 76 69 64 65 64 67 68 61 64 6d 75 6c 74 69 70 6c 79 59 62 72 69 6e 67 78 4d 61 6c 65 } //1 thingdividedghadmultiplyYbringxMale
		$a_01_1 = {43 72 65 65 70 65 74 68 59 77 68 65 72 65 69 6e } //1 CreepethYwherein
		$a_01_2 = {45 61 6c 45 73 6e 65 61 74 61 79 73 78 78 74 } //1 EalEsneataysxxt
		$a_80_3 = {4f 4e 46 49 37 77 54 73 65 74 72 66 6c 79 } //ONFI7wTsetrfly  1
		$a_80_4 = {68 6d 79 79 6f 75 77 69 6e 67 65 64 4c 68 65 63 72 65 65 70 69 6e 67 } //hmyyouwingedLhecreeping  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}