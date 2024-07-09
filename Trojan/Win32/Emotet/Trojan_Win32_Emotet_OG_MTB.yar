
rule Trojan_Win32_Emotet_OG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.OG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 e2 ff 00 00 00 89 [0-05] 8b [0-05] 8a [0-02] 30 [0-02] 8b [0-05] 8b [0-05] 8a [0-02] 30 [0-02] 8b [0-05] 8b [0-05] 8a [0-02] 30 [0-02] ff [0-05] 8b [0-05] 3d [0-64] 81 ?? ff 00 00 00 [0-4b] 30 [0-4b] 30 } //1
		$a_02_1 = {6a 40 68 00 10 00 00 [0-23] 83 c4 0c [0-23] 6a 00 6a 01 6a 00 [0-96] 83 c4 0c [0-0f] ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}