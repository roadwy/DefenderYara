
rule Trojan_O97M_Obfuse_RLP_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.RLP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 78 65 2e 79 74 74 75 70 2f 33 32 31 2f 32 33 31 2e 30 33 31 2e 32 37 31 2e 37 30 31 2f 2f 3a 70 74 74 68 } //01 00  exe.yttup/321/231.031.271.701//:ptth
		$a_01_1 = {73 74 72 72 65 76 65 72 73 65 28 22 5c 30 2e 31 76 5c 6c 6c 65 68 73 72 65 77 6f 70 73 77 6f 64 6e 69 77 5c 32 33 6d 65 74 73 79 73 5c 73 77 6f 64 6e 69 77 5c 3a 63 22 29 29 65 6e 64 73 75 62 } //00 00  strreverse("\0.1v\llehsrewopswodniw\23metsys\swodniw\:c"))endsub
	condition:
		any of ($a_*)
 
}