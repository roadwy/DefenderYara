
rule Trojan_AndroidOS_Smforw_H{
	meta:
		description = "Trojan:AndroidOS/Smforw.H,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {69 6e 64 65 78 2e 70 68 70 3f 74 79 70 65 3d 72 65 63 65 69 76 65 73 6d 73 26 74 65 6c 6e 75 6d 3d } //2 index.php?type=receivesms&telnum=
		$a_01_1 = {41 6c 6c 6f 77 5f 41 75 74 6f 43 61 6c 6c } //2 Allow_AutoCall
		$a_01_2 = {53 4d 53 5f 42 6c 6f 63 6b 53 74 61 74 65 } //2 SMS_BlockState
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}