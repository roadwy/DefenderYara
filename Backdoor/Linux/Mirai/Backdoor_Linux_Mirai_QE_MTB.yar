
rule Backdoor_Linux_Mirai_QE_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.QE!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {89 3d 00 00 2f 89 00 2e 41 9e 03 14 2f 89 00 00 41 9e 03 0c 38 0a 00 01 99 2b 00 00 54 0a 06 3e 39 6b 00 01 3b bd 00 01 42 00 ff d8 } //01 00 
		$a_00_1 = {62 65 61 72 64 72 6f 70 70 65 72 } //01 00  beardropper
		$a_00_2 = {74 30 74 61 6c 63 30 6e 74 72 30 6c 34 21 } //01 00  t0talc0ntr0l4!
		$a_00_3 = {77 61 62 6a 74 61 6d } //00 00  wabjtam
	condition:
		any of ($a_*)
 
}