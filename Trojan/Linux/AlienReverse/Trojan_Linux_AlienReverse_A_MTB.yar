
rule Trojan_Linux_AlienReverse_A_MTB{
	meta:
		description = "Trojan:Linux/AlienReverse.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 41 6c 69 65 6e 52 65 76 65 72 73 65 } //1 /AlienReverse
		$a_01_1 = {2d 2d 72 65 76 65 72 73 65 2d 61 64 64 72 65 73 73 3d } //1 --reverse-address=
		$a_01_2 = {31 33 43 53 68 65 6c 6c 4d 61 6e 61 67 65 72 } //1 13CShellManager
		$a_01_3 = {53 79 73 52 65 76 65 72 73 65 } //1 SysReverse
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}