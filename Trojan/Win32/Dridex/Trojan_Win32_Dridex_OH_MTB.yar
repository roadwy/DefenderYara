
rule Trojan_Win32_Dridex_OH_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {b0 61 8a 4c 24 ?? 80 [0-02] 8b [0-03] 88 [0-03] 8b [0-02] 66 8b [0-03] 66 89 [0-03] 03 [0-02] 8a [0-03] 89 [0-03] 8b [0-03] 89 [0-03] 8b [0-02] 8b [0-02] 03 [0-03] 89 [0-03] 8a [0-03] 80 [0-02] 88 [0-03] 8b [0-03] 2b [0-03] 8b [0-02] 89 [0-03] 8b [0-02] 89 [0-03] 38 c8 72 } //1
		$a_81_1 = {5f 65 73 5f 5f 70 70 5f 5f 5f 5f } //1 _es__pp____
		$a_81_2 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //1 OutputDebugStringA
		$a_81_3 = {73 65 6c 66 2e 65 78 } //1 self.ex
		$a_81_4 = {41 76 69 72 61 20 47 6d 62 48 } //1 Avira GmbH
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}