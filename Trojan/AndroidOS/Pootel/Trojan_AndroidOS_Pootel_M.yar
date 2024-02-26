
rule Trojan_AndroidOS_Pootel_M{
	meta:
		description = "Trojan:AndroidOS/Pootel.M,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 20 6b 68 6f 6e 67 20 62 61 6d 20 67 75 69 } //01 00  User khong bam gui
		$a_01_1 = {44 69 67 69 5f 4d 6f 62 69 6c 5f 32 32 36 30 35 } //00 00  Digi_Mobil_22605
	condition:
		any of ($a_*)
 
}