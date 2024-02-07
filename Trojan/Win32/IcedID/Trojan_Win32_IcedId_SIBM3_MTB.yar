
rule Trojan_Win32_IcedId_SIBM3_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBM3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 78 70 65 72 69 65 6e 63 65 45 78 65 72 63 69 73 65 } //01 00  ExperienceExercise
		$a_03_1 = {83 c2 04 89 55 90 01 01 81 7d 90 1b 00 90 01 04 0f 83 90 01 04 90 08 80 01 8b 0d 90 01 04 03 4d 90 1b 00 8b 91 90 01 04 89 15 90 01 04 90 08 f0 01 8b 15 90 1b 08 81 c2 90 01 04 89 15 90 1b 08 a1 90 1b 05 03 45 90 1b 00 8b 0d 90 1b 08 89 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}