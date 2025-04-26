
rule Trojan_BAT_XShark_A_MTB{
	meta:
		description = "Trojan:BAT/XShark.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {58 53 68 61 72 6b 65 64 30 30 30 } //1 XSharked000
		$a_81_1 = {2f 63 6f 6d 6d 61 6e 64 2e 62 69 6e } //1 /command.bin
		$a_81_2 = {2f 72 65 73 75 6c 74 2e 62 69 6e } //1 /result.bin
		$a_81_3 = {2f 75 73 65 72 49 6e 66 6f 2e 70 68 70 } //1 /userInfo.php
		$a_81_4 = {53 65 72 76 65 72 58 53 68 61 72 6b } //1 ServerXShark
		$a_81_5 = {53 74 75 62 58 53 68 61 72 6b } //1 StubXShark
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}