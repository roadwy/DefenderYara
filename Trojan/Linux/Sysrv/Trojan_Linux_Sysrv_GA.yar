
rule Trojan_Linux_Sysrv_GA{
	meta:
		description = "Trojan:Linux/Sysrv.GA,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {65 78 70 2e 41 74 74 61 63 6b } //exp.Attack  01 00 
		$a_80_1 = {2f 65 78 70 2e 67 6f } ///exp.go  ff ff 
		$a_80_2 = {2f 6d 61 74 68 2f 72 61 6e 64 2f 65 78 70 2e 67 6f } ///math/rand/exp.go  01 00 
		$a_80_3 = {2f 7a 6d 61 70 2f } ///zmap/  00 00 
	condition:
		any of ($a_*)
 
}