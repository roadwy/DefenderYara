
rule Trojan_AndroidOS_Smsthief_AJ{
	meta:
		description = "Trojan:AndroidOS/Smsthief.AJ,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 41 6c 6c 53 6d 73 4e 6f 74 53 65 6e 64 65 64 59 65 74 } //1 GetAllSmsNotSendedYet
		$a_01_1 = {6f 66 66 6c 69 6e 65 73 6d 73 6e 75 6d 62 65 72 } //1 offlinesmsnumber
		$a_01_2 = {67 65 74 41 75 74 6f 68 69 64 65 61 66 74 65 72 73 65 63 6f 6e 64 73 } //1 getAutohideafterseconds
		$a_01_3 = {55 50 44 41 54 45 20 6f 66 66 6c 69 6e 65 73 6d 73 20 73 65 74 20 69 73 73 65 6e 64 3d 31 20 77 68 65 72 65 20 69 64 20 3d 20 3f } //1 UPDATE offlinesms set issend=1 where id = ?
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}