
rule TrojanDownloader_Win32_Garveep_H{
	meta:
		description = "TrojanDownloader:Win32/Garveep.H,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 32 db b8 80 00 00 00 8d 78 ff 83 ff 7f 0f 87 } //5
		$a_01_1 = {44 45 58 54 38 37 } //3 DEXT87
		$a_00_2 = {2f 75 33 2f 75 70 64 61 74 65 2f 63 68 6b 75 70 64 61 74 65 2e 70 68 70 } //1 /u3/update/chkupdate.php
		$a_00_3 = {2f 75 33 2f 6e 6f 75 70 64 61 74 65 2f 75 70 64 61 74 65 2e 70 68 70 } //1 /u3/noupdate/update.php
		$a_00_4 = {2f 75 33 2f 75 70 64 61 74 65 2f 75 70 64 61 74 65 2e 70 68 70 } //1 /u3/update/update.php
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=9
 
}