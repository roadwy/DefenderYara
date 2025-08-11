
rule Trojan_Win32_Guloader_LXH_MTB{
	meta:
		description = "Trojan:Win32/Guloader.LXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {63 72 6f 77 64 69 6e 67 20 6c 69 6d 65 6c 69 6b 65 } //1 crowding limelike
		$a_81_1 = {66 6f 73 74 65 72 68 69 6e 64 65 20 70 72 6f 66 61 6e 65 64 2e 65 78 65 } //1 fosterhinde profaned.exe
		$a_81_2 = {62 61 64 65 73 74 65 64 65 74 } //1 badestedet
		$a_81_3 = {6b 6f 6c 6c 69 6e 67 20 74 72 6f 6e 61 67 65 } //1 kolling tronage
		$a_81_4 = {70 72 65 73 63 72 69 70 74 69 76 69 73 6d 2e 74 65 6e } //1 prescriptivism.ten
		$a_81_5 = {62 65 6c 6c 6d 61 6b 69 6e 67 2e 64 69 72 } //1 bellmaking.dir
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}