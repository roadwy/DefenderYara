
rule Trojan_Win64_FateGrab_JM_MTB{
	meta:
		description = "Trojan:Win64/FateGrab.JM!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {44 8d 4f 03 45 32 0e 41 80 f1 09 48 3b ca 73 23 48 8d 41 01 48 89 44 24 40 48 8d 44 24 30 48 83 fa 10 48 0f 43 44 24 30 44 88 0c 08 c6 44 08 01 00 } //01 00 
		$a_01_1 = {4d 73 53 74 61 72 74 75 70 } //00 00  MsStartup
	condition:
		any of ($a_*)
 
}