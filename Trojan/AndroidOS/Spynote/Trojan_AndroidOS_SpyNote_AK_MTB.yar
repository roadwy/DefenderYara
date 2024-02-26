
rule Trojan_AndroidOS_SpyNote_AK_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyNote.AK!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 43 6f 6e 66 69 67 2f 73 79 73 2f 61 70 70 73 2f 6c 6f 67 2f 6c 6f 67 2d } //01 00  /Config/sys/apps/log/log-
		$a_00_1 = {41 63 74 69 76 53 65 6e 64 } //01 00  ActivSend
		$a_00_2 = {61 73 6b 6b 65 79 70 72 69 6d } //01 00  askkeyprim
		$a_00_3 = {67 65 74 72 65 71 75 69 65 72 64 70 72 69 6d 73 } //01 00  getrequierdprims
		$a_00_4 = {5f 61 73 6b 5f 72 65 6d 6f 76 65 5f } //01 00  _ask_remove_
		$a_00_5 = {6e 61 6d 65 5f 6b 65 79 } //01 00  name_key
		$a_00_6 = {41 75 74 6f 5f 43 6c 69 63 6b } //01 00  Auto_Click
		$a_00_7 = {73 63 72 65 65 6e 73 68 6f 74 72 65 73 75 6c 74 } //00 00  screenshotresult
	condition:
		any of ($a_*)
 
}