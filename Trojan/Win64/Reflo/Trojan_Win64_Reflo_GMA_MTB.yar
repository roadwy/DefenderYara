
rule Trojan_Win64_Reflo_GMA_MTB{
	meta:
		description = "Trojan:Win64/Reflo.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3f 52 65 66 6c 65 63 74 69 76 65 44 6c 6c 4d 61 69 6e 40 40 59 41 48 50 45 41 45 40 5a } //01 00  ?ReflectiveDllMain@@YAHPEAE@Z
		$a_01_1 = {5c 43 52 59 50 54 4f 43 4f 49 4e 5c 72 6f 6f 74 6b 69 74 5c 72 37 37 2d 72 6f 6f 74 6b 69 74 2d 6d 61 73 74 65 72 5f 31 2e 33 2e 30 5c 72 37 37 2d 72 6f 6f 74 6b 69 74 2d 6d 61 73 74 65 72 5c 76 73 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 72 37 37 2d 78 36 34 2e 70 64 62 } //00 00  \CRYPTOCOIN\rootkit\r77-rootkit-master_1.3.0\r77-rootkit-master\vs\x64\Release\r77-x64.pdb
	condition:
		any of ($a_*)
 
}