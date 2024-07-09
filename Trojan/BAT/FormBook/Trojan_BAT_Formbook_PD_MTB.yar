
rule Trojan_BAT_Formbook_PD_MTB{
	meta:
		description = "Trojan:BAT/Formbook.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {16 0c 2b 1f 06 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 26 08 18 d6 0c 08 07 31 dd 06 6f ?? 00 00 0a 2a } //1
		$a_02_1 = {0a 16 9a 13 ?? 11 ?? 72 ?? ?? ?? 70 20 00 01 00 00 14 14 1a 8d 01 00 00 01 13 ?? 11 ?? 16 [0-02] a2 11 ?? 17 [0-02] a2 11 ?? 18 [0-02] a2 11 [0-0a] 6f ?? 00 00 0a } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}