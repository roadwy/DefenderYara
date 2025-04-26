
rule Trojan_BAT_Redlinestealer_SL_MTB{
	meta:
		description = "Trojan:BAT/Redlinestealer.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {4c 65 66 74 77 61 72 64 73 20 47 72 61 6e 20 53 65 6e 73 61 74 69 6f 6e 61 6c 6c 79 } //2 Leftwards Gran Sensationally
		$a_81_1 = {53 74 65 72 65 6f 2e 65 78 65 } //2 Stereo.exe
		$a_81_2 = {54 65 6c 65 67 72 61 70 68 69 63 61 6c 6c 79 20 4e 69 6c } //2 Telegraphically Nil
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}