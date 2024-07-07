
rule Trojan_AndroidOS_Spynote_L_MTB{
	meta:
		description = "Trojan:AndroidOS/Spynote.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_00_0 = {73 63 72 65 65 6e 73 68 6f 74 72 65 73 75 6c 74 } //1 screenshotresult
		$a_00_1 = {67 65 74 72 65 71 75 69 65 72 64 70 72 69 6d 73 } //1 getrequierdprims
		$a_00_2 = {67 65 74 6d 65 74 32 } //1 getmet2
		$a_00_3 = {61 73 6b 5f 62 61 74 74 61 72 79 } //1 ask_battary
		$a_00_4 = {69 73 65 6d 75 5f 64 69 76 5f 69 64 5f 6c 61 74 6f 72 } //1 isemu_div_id_lator
		$a_00_5 = {41 63 74 69 76 53 65 6e 64 } //1 ActivSend
		$a_00_6 = {2f 43 6f 6e 66 69 67 2f 73 79 73 2f 61 70 70 73 2f 6c 6f 67 2f 6c 6f 67 2d } //1 /Config/sys/apps/log/log-
		$a_00_7 = {56 48 68 55 65 46 51 3d } //1 VHhUeFQ=
		$a_00_8 = {41 73 6b 4b 65 79 50 72 69 6d } //1 AskKeyPrim
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=6
 
}