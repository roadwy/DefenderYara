
rule Trojan_Linux_Reptile_B{
	meta:
		description = "Trojan:Linux/Reptile.B,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 72 65 70 74 69 6c 65 2f 72 65 70 74 69 6c 65 5f 73 68 65 6c 6c } //1 /reptile/reptile_shell
		$a_01_1 = {2f 72 65 70 74 69 6c 65 2f 72 65 70 74 69 6c 65 5f 73 74 61 72 74 } //1 /reptile/reptile_start
		$a_01_2 = {6e 61 6d 65 3d 72 65 70 74 69 6c 65 5f 6d 6f 64 75 6c 65 } //1 name=reptile_module
		$a_01_3 = {68 61 78 30 72 } //1 hax0r
		$a_01_4 = {73 33 63 72 33 74 } //1 s3cr3t
		$a_01_5 = {23 3c 72 65 70 74 69 6c 65 3e } //1 #<reptile>
		$a_01_6 = {23 3c 2f 72 65 70 74 69 6c 65 3e } //1 #</reptile>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=4
 
}