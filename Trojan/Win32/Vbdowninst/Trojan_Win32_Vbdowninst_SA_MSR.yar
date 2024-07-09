
rule Trojan_Win32_Vbdowninst_SA_MSR{
	meta:
		description = "Trojan:Win32/Vbdowninst.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 69 70 72 61 73 2e 76 62 73 } //1 :\ProgramData\ipras.vbs
		$a_01_1 = {69 70 6c 6f 67 67 65 72 2e 6f 72 67 2f } //1 iplogger.org/
		$a_02_2 = {5c 49 6e 69 73 74 61 6c 6c [0-02] 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}