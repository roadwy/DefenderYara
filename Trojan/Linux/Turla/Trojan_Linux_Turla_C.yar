
rule Trojan_Linux_Turla_C{
	meta:
		description = "Trojan:Linux/Turla.C,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {73 74 61 63 6b 20 3d 20 30 78 25 78 2c 20 74 61 72 67 5f 61 64 64 72 20 3d 20 30 78 25 78 } //stack = 0x%x, targ_addr = 0x%x  1
		$a_80_1 = {65 78 65 63 6c 20 66 61 69 6c 65 64 } //execl failed  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}