
rule Ransom_Linux_Babuk_S_MTB{
	meta:
		description = "Ransom:Linux/Babuk.S!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5f 72 5f 65 5f 61 5f 64 5f 6d 5f 65 2e 74 78 74 } //1 _r_e_a_d_m_e.txt
		$a_01_1 = {2e 63 6c 70 6d 77 65 } //1 .clpmwe
		$a_01_2 = {78 79 63 71 6d 77 74 69 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67 } //1 xycqmwti@onionmail.org
		$a_01_3 = {2e 6c 6f 67 2c 2e 76 6d 64 6b 2c 2e 76 6d 65 6d 2c 2e 76 73 77 70 2c 2e 76 6d 73 6e 2c 2e 76 6d 73 64 2c 2e 76 6d 78 2c 2e 67 7a } //1 .log,.vmdk,.vmem,.vswp,.vmsn,.vmsd,.vmx,.gz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}