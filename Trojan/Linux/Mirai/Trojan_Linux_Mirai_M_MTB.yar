
rule Trojan_Linux_Mirai_M_MTB{
	meta:
		description = "Trojan:Linux/Mirai.M!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 75 69 2f 6c 6f 63 61 6c 6c 62 2f 77 6f 72 6b 73 70 61 63 65 2f 74 6d 73 68 43 6d 64 2e 6a 73 70 } //1 /tmui/locallb/workspace/tmshCmd.jsp
		$a_00_1 = {2f 6c 69 6e 75 78 6b 69 34 34 33 2f 65 78 70 65 72 69 6d 65 6e 74 61 6c 2f 76 69 73 2f 6b 69 34 34 33 76 69 73 2e 70 68 70 } //1 /linuxki443/experimental/vis/ki443vis.php
		$a_00_2 = {64 69 61 67 5f 70 69 6e 67 5f 61 64 6d 69 6e 5f 65 6e 2e 61 73 70 } //1 diag_ping_admin_en.asp
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}