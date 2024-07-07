
rule Trojan_Win64_Kriskynote_A_dha{
	meta:
		description = "Trojan:Win64/Kriskynote.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 79 72 61 72 62 69 4c 64 61 6f 4c } //1 AyrarbiLdaoL
		$a_01_1 = {49 6e 73 74 61 6c 6c 5f 75 61 63 } //1 Install_uac
		$a_00_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 5c 50 61 72 61 6d 65 74 65 72 73 } //1 SYSTEM\CurrentControlSet\Services\%s\Parameters
		$a_01_3 = {00 49 6e 73 74 61 6c 6c 00 44 65 6c 65 74 65 46 00 } //1
		$a_01_4 = {8a 04 31 34 36 8a d0 80 e2 0f c0 e2 04 c0 e8 04 02 d0 88 14 31 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}