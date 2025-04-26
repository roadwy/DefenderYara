
rule Trojan_Win32_Babar_RC_MTB{
	meta:
		description = "Trojan:Win32/Babar.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 41 54 20 2d 20 53 45 52 56 45 52 } //1 RAT - SERVER
		$a_01_1 = {45 78 69 74 20 52 41 54 20 63 68 61 74 } //1 Exit RAT chat
		$a_81_2 = {43 45 53 53 41 32 30 32 30 5c 55 54 49 4c 45 52 49 41 53 5c 72 61 74 62 79 74 68 65 64 61 79 77 61 6c 6b 65 72 5c 70 72 6f 6a 65 63 74 5c 73 65 72 76 65 72 5c 73 65 72 76 65 72 2e 76 62 70 } //1 CESSA2020\UTILERIAS\ratbythedaywalker\project\server\server.vbp
		$a_81_3 = {44 65 73 6b 74 6f 70 20 48 69 64 64 65 6e } //1 Desktop Hidden
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}