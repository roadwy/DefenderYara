
rule Trojan_Win32_Trickbot_GR_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 73 0c 03 f7 8b ea 3b e9 76 [0-07] 8b 44 24 14 83 78 18 ?? 72 ?? 83 c0 ?? 8b 00 eb ?? 83 c0 ?? 8a 0c 28 30 0e 8b 43 10 2b 43 0c 47 3b f8 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Trickbot_GR_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8b c1 [0-08] f7 [0-02] 8b [0-03] 8a [0-02] 8a [0-04] 32 [0-04] 88 [0-02] 41 81 f9 } //10
		$a_02_1 = {73 00 66 c7 [0-04] 77 00 66 [0-04] 68 00 66 [0-04] 6b 00 66 [0-04] 2e 00 66 [0-04] 64 00 } //1
		$a_02_2 = {61 00 66 c7 [0-02] 73 00 66 c7 [0-02] 77 00 66 c7 [0-02] 68 00 66 c7 [0-02] 6f 00 66 c7 [0-02] 6f 00 66 c7 [0-02] 6b 00 66 c7 [0-02] 2e 00 66 c7 [0-02] 64 00 66 c7 [0-02] 6c 00 66 c7 [0-02] 6c 00 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=11
 
}