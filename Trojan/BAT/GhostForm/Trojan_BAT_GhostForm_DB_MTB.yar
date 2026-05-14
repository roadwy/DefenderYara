
rule Trojan_BAT_GhostForm_DB_MTB{
	meta:
		description = "Trojan:BAT/GhostForm.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,68 00 68 00 05 00 00 "
		
	strings :
		$a_81_0 = {45 6e 74 65 72 20 70 61 73 73 77 6f 72 64 } //1 Enter password
		$a_81_1 = {54 68 65 20 64 6f 77 6e 6c 6f 61 64 20 64 69 64 20 6e 6f 74 20 63 6f 6d 70 6c 65 74 65 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 The download did not complete successfully
		$a_81_2 = {63 3a 5c 70 72 6f 67 72 61 6d 44 61 74 61 } //1 c:\programData
		$a_81_3 = {50 6f 6c 47 75 69 64 } //100 PolGuid
		$a_81_4 = {5c 56 4c 43 5c 56 4c 43 2e 65 78 65 } //1 \VLC\VLC.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*100+(#a_81_4  & 1)*1) >=104
 
}