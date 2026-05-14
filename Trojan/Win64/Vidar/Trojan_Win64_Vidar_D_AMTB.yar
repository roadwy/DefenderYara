
rule Trojan_Win64_Vidar_D_AMTB{
	meta:
		description = "Trojan:Win64/Vidar.D!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {44 45 41 44 42 45 45 46 } //2 DEADBEEF
		$a_81_1 = {46 69 72 65 66 6f 78 20 50 6c 75 67 69 6e 73 } //1 Firefox Plugins
		$a_81_2 = {46 69 6c 65 20 47 72 61 62 62 65 72 20 52 75 6c 65 73 } //1 File Grabber Rules
		$a_81_3 = {4c 6f 61 64 65 72 20 54 61 73 6b 73 } //1 Loader Tasks
		$a_81_4 = {5c 4e 65 74 77 6f 72 6b 5c 43 6f 6f 6b 69 65 73 } //1 \Network\Cookies
		$a_81_5 = {42 72 6f 77 73 65 72 20 4c 69 73 74 } //1 Browser List
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}