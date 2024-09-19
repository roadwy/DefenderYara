
rule Trojan_BAT_Formbook_NW_MTB{
	meta:
		description = "Trojan:BAT/Formbook.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_81_0 = {39 34 65 36 39 32 64 34 2d 65 39 36 34 2d 34 38 34 64 2d 38 39 31 62 2d 62 39 34 63 30 36 66 36 35 35 32 32 } //5 94e692d4-e964-484d-891b-b94c06f65522
		$a_81_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_2 = {73 65 74 5f 50 61 73 73 77 6f 72 64 43 68 61 72 } //1 set_PasswordChar
		$a_81_3 = {67 65 74 5f 50 61 73 73 77 6f 72 64 } //1 get_Password
		$a_81_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=9
 
}
rule Trojan_BAT_Formbook_NW_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 97 a2 2b 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 81 00 00 00 31 00 00 00 d2 00 00 00 } //1
		$a_01_1 = {50 61 63 4d 61 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 PacMan.Properties.Resources.resource
		$a_01_2 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}