
rule Trojan_Win32_TampEnum_A_MTB{
	meta:
		description = "Trojan:Win32/TampEnum.A!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 } //1 tasklist
		$a_00_1 = {69 00 6d 00 61 00 67 00 65 00 6e 00 61 00 6d 00 65 00 20 00 65 00 71 00 20 00 4d 00 73 00 4d 00 70 00 45 00 6e 00 67 00 2e 00 65 00 78 00 65 00 } //1 imagename eq MsMpEng.exe
		$a_00_2 = {66 00 69 00 6e 00 64 00 } //1 find
		$a_00_3 = {50 00 49 00 44 00 } //1 PID
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}