
rule Trojan_BAT_AveMariaRAT_NYD_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.NYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 00 65 00 73 00 6f 00 00 07 75 00 72 00 63 00 00 05 65 00 73 } //01 00 
		$a_01_1 = {4d 00 61 00 6e 00 64 00 6c 00 6f 00 70 00 67 00 66 00 63 00 6a 00 64 00 67 00 66 00 } //01 00  Mandlopgfcjdgf
		$a_01_2 = {7a 00 7a 00 4d 00 7a 00 65 00 7a 00 74 00 7a 00 68 00 7a 00 6f 00 7a 00 7a 00 7a 00 64 00 7a 00 30 00 7a 00 7a 00 7a 00 7a 00 7a 00 } //01 00  zzMzeztzhzozzzdz0zzzzz
		$a_01_3 = {47 00 65 00 74 00 4d 00 61 00 6e 00 69 00 66 00 65 00 73 00 74 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 4e 00 61 00 6d 00 65 00 73 00 } //00 00  GetManifestResourceNames
	condition:
		any of ($a_*)
 
}