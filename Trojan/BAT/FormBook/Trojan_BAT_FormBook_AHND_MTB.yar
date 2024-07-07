
rule Trojan_BAT_FormBook_AHND_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AHND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 91 61 28 90 01 03 0a 07 09 17 58 90 00 } //2
		$a_01_1 = {44 00 65 00 70 00 6c 00 6f 00 79 00 6d 00 65 00 6e 00 74 00 5f 00 53 00 69 00 6d 00 75 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Deployment_Simulation
		$a_01_2 = {50 00 69 00 40 00 73 00 2e 00 57 00 68 00 69 00 74 00 40 00 } //1 Pi@s.Whit@
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}