
rule Trojan_O97M_Obfuse_RT_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.RT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 73 68 65 6c 6c 65 78 65 63 75 74 65 28 31 2c 73 74 72 72 65 76 65 72 73 65 28 22 6e 65 70 6f 22 29 2c 73 74 72 72 65 76 65 72 73 65 28 22 65 78 65 2e 6c 6c 65 68 73 72 65 77 6f 70 22 29 2c 73 74 72 72 65 76 65 72 73 65 28 22 65 78 65 2e 79 74 74 75 70 5c 70 6d 65 74 5c 73 77 6f 64 6e 69 77 5c 3a 63 65 78 65 2e 72 65 72 6f 6c 70 78 65 3b 65 78 65 2e 79 74 74 75 70 5c 70 6d 65 74 5c 73 77 6f 64 6e 69 77 5c 3a 63 6f 2d 65 78 65 } //00 00  =shellexecute(1,strreverse("nepo"),strreverse("exe.llehsrewop"),strreverse("exe.yttup\pmet\swodniw\:cexe.rerolpxe;exe.yttup\pmet\swodniw\:co-exe
	condition:
		any of ($a_*)
 
}