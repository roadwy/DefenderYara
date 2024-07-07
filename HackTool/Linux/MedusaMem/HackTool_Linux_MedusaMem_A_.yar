
rule HackTool_Linux_MedusaMem_A_{
	meta:
		description = "HackTool:Linux/MedusaMem.A!!MedusaMem.A,SIGNATURE_TYPE_ARHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {4a 6f 4d 6f 2d 4b 75 6e 20 2f 20 46 6f 6f 66 75 73 20 4e 65 74 77 6f 72 6b 73 } //2 JoMo-Kun / Foofus Networks
		$a_00_1 = {23 20 4d 65 64 75 73 61 20 68 61 73 20 66 69 6e 69 73 68 65 64 20 28 25 73 29 } //2 # Medusa has finished (%s)
		$a_00_2 = {23 20 4d 65 64 75 73 61 20 76 2e 25 73 20 28 25 73 29 } //2 # Medusa v.%s (%s)
		$a_00_3 = {54 6f 74 61 6c 20 50 61 73 73 77 6f 72 64 73 3a 20 5b 63 6f 6d 62 6f 5d } //2 Total Passwords: [combo]
		$a_00_4 = {54 6f 74 61 6c 20 55 73 65 72 73 3a 20 5b 63 6f 6d 62 6f 5d } //2 Total Users: [combo]
		$a_00_5 = {3a 20 46 69 6c 65 20 63 6f 6e 74 61 69 6e 69 6e 67 20 70 61 73 73 77 6f 72 64 73 20 74 6f 20 74 65 73 74 } //2 : File containing passwords to test
		$a_01_6 = {6d 65 64 75 73 61 43 6f 6e 6e 65 63 74 53 53 4c 49 6e 74 65 72 6e 61 6c } //2 medusaConnectSSLInternal
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}