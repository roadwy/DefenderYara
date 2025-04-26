
rule Trojan_WinNT_Adwind_BH_MTB{
	meta:
		description = "Trojan:WinNT/Adwind.BH!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6e 65 6b 6c 6b 63 68 6b 6c 6d 2e 76 62 73 } //1 neklkchklm.vbs
		$a_00_1 = {72 65 73 6f 75 72 63 65 73 2f 79 79 72 67 6c 78 77 6e 75 74 } //1 resources/yyrglxwnut
		$a_00_2 = {4d 62 68 6f 63 6a 72 74 65 66 79 } //1 Mbhocjrtefy
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}