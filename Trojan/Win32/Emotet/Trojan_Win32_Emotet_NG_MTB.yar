
rule Trojan_Win32_Emotet_NG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 10 00 00 [0-23] 83 c4 0c [0-23] f7 d8 1b c0 [0-96] 83 c4 0c ff d0 } //1
		$a_02_1 = {81 e2 ff 00 00 00 c1 [0-02] 8b [0-03] 0b [0-02] c1 [0-02] 33 ?? 3b 74 [0-02] 89 [0-02] 8d 76 [0-04] 0f [0-4b] 81 ?? ff 00 00 00 [0-03] 32 ?? 8d [0-02] 8b [0-02] 3b [0-02] [0-0f] e9 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}