
rule Worm_BAT_Najm_A_MTB{
	meta:
		description = "Worm:BAT/Najm.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 0d 00 06 00 00 "
		
	strings :
		$a_02_0 = {0a 00 06 0b 16 0c 38 86 ?? ?? ?? 07 08 9a 0d 00 09 6f ?? ?? ?? 0a 73 ?? ?? ?? 0a 13 04 11 04 6f ?? ?? ?? 0a 2c 0c 11 04 6f ?? ?? ?? 0a 18 fe 01 2b 01 16 13 05 11 05 2c 53 00 11 04 } //10
		$a_80_1 = {4e 61 6a 6d } //Najm  5
		$a_80_2 = {4e 61 6a 6d 5f 69 6e 66 6f } //Najm_info  4
		$a_80_3 = {66 72 6d 5f 66 61 6c 65 79 61 5f 61 61 6d 61 } //frm_faleya_aama  3
		$a_80_4 = {66 72 6d 5f 6a 61 77 61 6e 61 6e } //frm_jawanan  3
		$a_80_5 = {66 72 6d 5f 6e 61 73 68 61 72 61 74 } //frm_nasharat  3
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*4+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=13
 
}