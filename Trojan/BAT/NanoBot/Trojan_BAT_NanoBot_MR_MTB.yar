
rule Trojan_BAT_NanoBot_MR_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {50 6f 73 74 69 65 5f 4e 6f 74 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Postie_Notes.Resources.resources
		$a_81_1 = {67 65 74 5f 50 6f 73 74 69 65 4e 6f 74 65 } //1 get_PostieNote
		$a_81_2 = {67 65 74 5f 4c 69 73 74 49 44 50 65 67 61 77 61 69 } //1 get_ListIDPegawai
		$a_81_3 = {5f 4e 6f 77 42 74 6e } //1 _NowBtn
		$a_81_4 = {66 6f 72 6d 5f 72 65 66 49 64 4f 62 61 74 5f 4c 6f 61 64 } //1 form_refIdObat_Load
		$a_81_5 = {42 69 74 6d 61 70 } //1 Bitmap
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}