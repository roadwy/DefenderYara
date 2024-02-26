
rule Trojan_BAT_FileCoder_ARA_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_80_0 = {2e 46 75 63 6b 4f 66 66 } //.FuckOff  02 00 
		$a_80_1 = {5c 55 72 46 69 6c 65 2e 54 58 54 } //\UrFile.TXT  02 00 
		$a_80_2 = {59 6f 75 20 68 61 76 65 20 42 65 65 6e 20 48 61 63 6b 33 64 } //You have Been Hack3d  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_FileCoder_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/FileCoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 07 9a 0c 00 08 28 90 01 03 06 00 08 28 90 01 03 06 00 00 07 17 58 0b 07 06 8e 69 32 e2 90 00 } //02 00 
		$a_80_1 = {5c 4c 6f 63 6b 42 49 54 5c 73 79 73 74 65 6d 49 44 } //\LockBIT\systemID  00 00 
	condition:
		any of ($a_*)
 
}