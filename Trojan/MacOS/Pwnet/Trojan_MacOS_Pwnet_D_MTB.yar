
rule Trojan_MacOS_Pwnet_D_MTB{
	meta:
		description = "Trojan:MacOS/Pwnet.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 6e 6a 65 63 74 65 64 } //01 00  Injected
		$a_00_1 = {2f 44 6f 77 6e 6c 6f 61 64 73 2f 47 4f 2d 53 58 2d 49 6e 74 65 72 6e 61 6c 2d 4c 69 74 65 2d 6d 61 73 74 65 72 2f 6f 73 78 69 6e 6a 2f 6d 61 63 68 5f 69 6e 6a 65 63 74 } //01 00  /Downloads/GO-SX-Internal-Lite-master/osxinj/mach_inject
		$a_02_2 = {8a 85 c7 fe ff ff 34 ff 24 01 0f b6 c8 48 63 d1 48 83 fa 00 0f 84 90 01 04 48 8d 3d ab 11 00 00 48 8d 35 b0 11 00 00 48 8d 0d 16 12 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_MacOS_Pwnet_D_MTB_2{
	meta:
		description = "Trojan:MacOS/Pwnet.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {6f 73 78 69 6e 6a 2f 6d 61 63 68 5f 69 6e 6a 65 63 74 2e 63 } //01 00  osxinj/mach_inject.c
		$a_00_1 = {2e 2f 6f 73 78 69 6e 6a 20 5b 70 72 6f 63 5f 6e 61 6d 65 5d 20 5b 6c 69 62 5d } //01 00  ./osxinj [proc_name] [lib]
		$a_00_2 = {2e 2f 6f 73 78 69 6e 6a 20 5b 70 69 64 5d 20 5b 6c 69 62 5d } //01 00  ./osxinj [pid] [lib]
		$a_00_3 = {69 6e 6a 65 63 74 6f 72 2e 63 70 70 } //01 00  injector.cpp
		$a_02_4 = {2f 6f 73 78 69 6e 6a 2e 62 75 69 6c 64 2f 90 02 07 2f 6f 73 78 69 6e 6a 2e 62 75 69 6c 64 90 00 } //01 00 
		$a_02_5 = {2f 67 6f 73 78 69 6e 6a 2e 62 75 69 6c 64 2f 90 02 07 2f 67 6f 73 78 69 6e 6a 2e 62 75 69 6c 64 90 00 } //01 00 
		$a_00_6 = {70 6c 65 61 73 65 20 72 75 6e 20 6d 65 20 61 73 20 72 6f 6f 74 } //00 00  please run me as root
	condition:
		any of ($a_*)
 
}