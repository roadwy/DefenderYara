
rule Worm_Win32_Flukan_C{
	meta:
		description = "Worm:Win32/Flukan.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 00 6c 00 75 00 5f 00 49 00 6b 00 61 00 6e 00 2e 00 76 00 62 00 70 00 } //01 00  Flu_Ikan.vbp
		$a_01_1 = {54 69 6d 65 72 5f 45 6e 53 63 72 69 70 74 } //01 00  Timer_EnScript
		$a_01_2 = {74 6d 72 5f 72 65 67 5f 76 69 72 75 73 } //01 00  tmr_reg_virus
		$a_01_3 = {69 6e 66 65 6b 73 69 5f 6d 69 72 63 } //00 00  infeksi_mirc
	condition:
		any of ($a_*)
 
}