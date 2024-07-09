
rule Trojan_BAT_AgentTesla_OR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {25 16 09 8c [0-04] a2 25 17 11 ?? 8c [0-04] a2 28 [0-04] 25 [0-02] 26 [0-02] fe [0-05] 11 ?? 2b ?? a5 [0-04] 13 ?? 11 ?? 28 } //1
		$a_81_1 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_81_2 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_3 = {67 65 74 5f 48 65 69 67 68 74 } //1 get_Height
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}