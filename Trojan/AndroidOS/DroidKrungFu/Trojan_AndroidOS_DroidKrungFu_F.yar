
rule Trojan_AndroidOS_DroidKrungFu_F{
	meta:
		description = "Trojan:AndroidOS/DroidKrungFu.F,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2f 6c 6f 67 6f 90 01 02 6d 79 6c 6f 67 6f 2e 6a 70 67 90 01 02 2f 73 79 73 74 65 6d 2f 62 69 6e 2f 63 68 6d 6f 64 90 00 } //01 00 
		$a_01_1 = {73 79 73 74 65 6d 2f 78 62 69 6e 2f 63 68 6d 6f 64 20 30 37 35 35 } //01 00  system/xbin/chmod 0755
		$a_01_2 = {55 70 64 61 74 65 43 68 65 63 6b } //00 00  UpdateCheck
	condition:
		any of ($a_*)
 
}