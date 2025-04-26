
rule Trojan_Win32_Pandemia_A_dha{
	meta:
		description = "Trojan:Win32/Pandemia.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 61 6e 27 74 20 73 74 6f 70 20 73 65 72 76 69 63 65 20 3a 20 6d 6f 75 63 6c 61 73 73 } //1 Can't stop service : mouclass
		$a_01_1 = {64 65 6c 65 74 65 20 66 6f 6c 64 65 72 20 65 78 63 65 70 74 69 6f 6e 20 3a 20 } //1 delete folder exception : 
		$a_01_2 = {64 65 6c 65 74 65 20 66 69 6c 65 20 65 78 63 65 70 74 69 6f 6e 20 3a 20 } //1 delete file exception : 
		$a_01_3 = {41 70 70 20 53 74 61 72 74 20 57 6f 72 6b 20 21 21 21 21 } //1 App Start Work !!!!
		$a_01_4 = {53 74 61 72 74 20 54 69 6d 65 20 50 61 72 61 6d 73 20 3a 20 } //1 Start Time Params : 
		$a_01_5 = {52 65 61 64 20 54 69 6d 65 73 74 61 6d 70 20 3a 20 } //1 Read Timestamp : 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}