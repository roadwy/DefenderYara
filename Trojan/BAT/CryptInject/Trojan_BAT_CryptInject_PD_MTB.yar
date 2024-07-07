
rule Trojan_BAT_CryptInject_PD_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 50 00 61 00 79 00 2e 00 74 00 78 00 74 00 } //1 MACHINE\Microsoft\Pay.txt
		$a_01_1 = {53 00 74 00 61 00 67 00 65 00 32 00 2e 00 65 00 78 00 65 00 } //1 Stage2.exe
		$a_01_2 = {54 00 68 00 69 00 73 00 49 00 73 00 53 00 74 00 61 00 67 00 65 00 31 00 } //1 ThisIsStage1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_CryptInject_PD_MTB_2{
	meta:
		description = "Trojan:BAT/CryptInject.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 36 64 38 62 36 65 39 66 2d 32 37 62 33 2d 34 31 63 38 2d 39 39 62 33 2d 63 61 64 63 39 32 37 37 33 66 61 30 } //1 $6d8b6e9f-27b3-41c8-99b3-cadc92773fa0
		$a_81_1 = {67 65 74 5f 4d 64 69 43 68 69 6c 64 72 65 6e } //1 get_MdiChildren
		$a_81_2 = {73 65 74 5f 4d 64 69 50 61 72 65 6e 74 } //1 set_MdiParent
		$a_81_3 = {4d 44 49 50 61 72 65 6e 74 31 } //1 MDIParent1
		$a_81_4 = {44 61 6d 61 2e 4d 79 } //1 Dama.My
		$a_81_5 = {44 61 6d 61 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 Dama.My.Resources
		$a_81_6 = {44 61 6d 61 2e 4d 44 49 50 61 72 65 6e 74 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Dama.MDIParent1.resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}