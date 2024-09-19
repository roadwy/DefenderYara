
rule Trojan_Linux_Rootkit_B_MTB{
	meta:
		description = "Trojan:Linux/Rootkit.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 6f 6f 74 2d 73 68 65 6c 6c } //1 root-shell
		$a_01_1 = {75 6e 68 69 64 65 2d 70 69 64 } //1 unhide-pid
		$a_01_2 = {72 6f 6f 74 6b 69 74 20 4c 4b 4d } //1 rootkit LKM
		$a_01_3 = {68 69 64 65 2d 66 69 6c 65 } //1 hide-file
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}