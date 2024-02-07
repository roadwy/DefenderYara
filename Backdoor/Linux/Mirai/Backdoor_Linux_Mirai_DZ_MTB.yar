
rule Backdoor_Linux_Mirai_DZ_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DZ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {89 c2 83 ee 02 c1 e2 0b 31 c2 44 89 c0 c1 e8 13 89 d1 44 31 c0 c1 e9 08 31 c2 31 d1 66 89 0f 48 83 c7 02 } //01 00 
		$a_00_1 = {2f 75 73 72 2f 63 6f 6d 70 72 65 73 73 2f 62 69 6e 2f } //01 00  /usr/compress/bin/
		$a_00_2 = {6d 6e 74 2f 6d 74 64 2f 61 70 70 2f 67 75 69 } //00 00  mnt/mtd/app/gui
	condition:
		any of ($a_*)
 
}