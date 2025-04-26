
rule Ransom_Linux_Babuk_C_MTB{
	meta:
		description = "Ransom:Linux/Babuk.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 78 31 6e 47 78 31 6e 47 } //1 .x1nGx1nG
		$a_01_1 = {76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 67 65 74 61 6c 6c 76 6d 73 } //1 vim-cmd vmsvc/getallvms
		$a_01_2 = {6b 70 68 32 39 73 69 75 6b 38 40 73 6b 69 66 66 2e 63 6f 6d } //1 kph29siuk8@skiff.com
		$a_01_3 = {76 69 6d 2d 63 6d 64 20 76 6d 73 76 63 2f 70 6f 77 65 72 2e 73 68 75 74 64 6f 77 6e 20 25 73 } //1 vim-cmd vmsvc/power.shutdown %s
		$a_01_4 = {3d 3d 3d 5b 20 54 6f 20 52 65 73 74 6f 72 65 20 46 69 6c 65 73 20 5d 3d 3d 3d 2e 74 78 74 } //1 ===[ To Restore Files ]===.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}