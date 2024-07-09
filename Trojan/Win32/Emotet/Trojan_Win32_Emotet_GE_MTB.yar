
rule Trojan_Win32_Emotet_GE_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 14 2f 03 c2 33 d2 f7 35 [0-04] 58 2b c1 0f af c3 03 d0 8b 44 24 ?? 2b d6 8a 0c 3a 30 08 ff 44 24 ?? 8b 44 24 ?? 3b 44 24 ?? 0f 82 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Emotet_GE_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6b c6 44 24 [0-0a] 72 c6 44 [0-02] 6e [0-0a] c6 44 [0-02] 33 c6 44 [0-02] 32 c6 44 [0-02] 2e c6 44 [0-02] 64 [0-0f] ff [0-06] 8b f0 } //1
		$a_02_1 = {78 c6 44 24 [0-02] 65 [0-0c] ff 90 0a 50 00 c6 [0-03] 74 c6 [0-03] 61 c6 [0-03] 73 c6 [0-03] 6b c6 [0-03] 6d c6 [0-03] 67 c6 [0-03] 72 c6 [0-03] 2e c6 [0-03] 65 c6 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}