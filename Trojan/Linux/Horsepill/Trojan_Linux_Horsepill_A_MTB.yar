
rule Trojan_Linux_Horsepill_A_MTB{
	meta:
		description = "Trojan:Linux/Horsepill.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 68 20 2d 63 20 27 75 70 64 61 74 65 2d 69 6e 69 74 72 61 6d 66 73 20 2d 6b 20 61 6c 6c 20 2d 75 20 32 } //1 sh -c 'update-initramfs -k all -u 2
		$a_01_1 = {2f 72 65 69 6e 66 65 63 74 2d } //1 /reinfect-
		$a_01_2 = {6d 6b 73 74 6d 70 } //1 mkstmp
		$a_01_3 = {73 70 6c 61 74 5f 66 69 6c 65 } //1 splat_file
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}