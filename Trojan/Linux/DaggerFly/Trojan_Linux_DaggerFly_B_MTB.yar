
rule Trojan_Linux_DaggerFly_B_MTB{
	meta:
		description = "Trojan:Linux/DaggerFly.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 72 65 61 64 79 20 69 6e 6a 65 63 74 21 } //1 aready inject!
		$a_01_1 = {69 6e 6a 65 63 74 5f 69 6e 69 74 20 4f 4b } //1 inject_init OK
		$a_01_2 = {50 6f 77 65 72 4f 6e 46 72 6f 6d 4e 65 74 20 62 69 6e 64 } //1 PowerOnFromNet bind
		$a_01_3 = {67 65 74 20 6d 61 67 69 63 5f 6e 61 6d 65 } //1 get magic_name
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}