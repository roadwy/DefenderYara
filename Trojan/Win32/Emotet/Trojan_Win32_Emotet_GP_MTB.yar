
rule Trojan_Win32_Emotet_GP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c1 8b cb c1 [0-02] 33 c1 8b cb c1 [0-02] c1 [0-02] c1 [0-02] 81 [0-05] c1 [0-02] 33 ?? 81 [0-05] 33 ?? ff [0-07] 0f [0-02] 3b [0-07] 5e 8b c3 [0-03] f7 d0 c3 } //1
		$a_00_1 = {f7 d8 1b c0 23 c6 5f 5e 5b c9 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}