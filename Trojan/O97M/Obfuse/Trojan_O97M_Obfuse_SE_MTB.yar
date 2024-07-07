
rule Trojan_O97M_Obfuse_SE_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.SE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 6f 75 72 6e 6f 77 3d 68 6f 75 72 28 74 69 6d 65 28 29 29 69 66 68 6f 75 72 6e 6f 77 3c 33 30 74 68 65 6e } //1 hournow=hour(time())ifhournow<30then
		$a_00_1 = {69 66 61 70 70 6c 69 63 61 74 69 6f 6e 2e 6f 70 65 72 61 74 69 6e 67 73 79 73 74 65 6d 6c 69 6b 65 22 2a 77 69 6e 64 6f 77 73 2a 22 74 68 65 6e } //1 ifapplication.operatingsystemlike"*windows*"then
		$a_00_2 = {77 69 6e 68 74 74 70 2e 77 69 6e 68 74 74 70 72 65 71 75 65 73 74 2e 35 2e 31 } //1 winhttp.winhttprequest.5.1
		$a_02_3 = {65 78 65 63 75 74 65 28 22 22 90 02 0f 3d 6e 6f 76 61 72 75 65 2b 22 22 22 22 74 79 70 65 64 76 61 6c 75 65 22 22 22 22 22 22 29 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}