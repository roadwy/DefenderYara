
rule Trojan_MacOS_Pwnet_E_MTB{
	meta:
		description = "Trojan:MacOS/Pwnet.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {44 65 73 6b 74 6f 70 2f 6f 73 78 69 6e 6a 2d 6d 61 73 74 65 72 2f 6f 73 78 69 6e 6a 2f 6d 61 63 68 5f 69 6e 6a 65 63 74 2e 63 } //01 00  Desktop/osxinj-master/osxinj/mach_inject.c
		$a_00_1 = {2e 2f 6f 73 78 69 6e 6a } //01 00  ./osxinj
		$a_00_2 = {70 6c 65 61 73 65 20 72 75 6e 20 6d 65 20 61 73 20 72 6f 6f 74 } //01 00  please run me as root
		$a_00_3 = {49 6e 6a 65 63 74 6f 72 90 01 02 67 65 74 50 72 6f 63 65 73 73 42 79 4e 61 6d 65 45 50 4b } //00 00 
		$a_00_4 = {5d 04 00 } //00 24 
	condition:
		any of ($a_*)
 
}