
rule VirTool_WinNT_Wiessy_A{
	meta:
		description = "VirTool:WinNT/Wiessy.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {80 7c 05 e0 ff 75 07 80 7c 05 e1 15 74 08 40 83 f8 12 72 ec eb 4e } //1
		$a_01_1 = {74 7e 89 75 e4 8b 7d f4 6a 02 59 8d 75 e8 33 c0 f3 a7 74 1e } //1
		$a_01_2 = {eb 4b 8b 10 fa 0f 20 c0 25 ff ff fe ff } //1
		$a_01_3 = {5c 00 3f 00 3f 00 5c 00 69 00 70 00 66 00 69 00 6c 00 6c 00 } //1 \??\ipfill
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}