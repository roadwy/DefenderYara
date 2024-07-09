
rule Trojan_Win32_Raccoonstlr_GG_MTB{
	meta:
		description = "Trojan:Win32/Raccoonstlr.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f3 33 75 [0-02] 2b fe 25 [0-04] 81 6d [0-05] bb [0-04] 81 45 [0-05] 8b 4d [0-02] 83 25 [0-04] 00 8b c7 d3 e0 8b cf c1 e9 [0-02] 03 4d [0-02] 03 45 [0-02] 33 c1 8b 4d [0-02] 03 cf 33 c1 [0-20] 8d 45 [0-02] e8 [0-04] ff 4d [0-02] 0f 85 [0-64] 89 7e [0-02] 5f 5e 5b c9 [0-64] 83 c6 [0-02] 4f 75 } //1
		$a_02_1 = {55 8b ec 51 a1 [0-04] 8b 15 [0-04] 89 45 [0-02] b8 [0-04] 01 45 [0-02] 8b 45 [0-02] 8a 04 [0-02] 88 04 [0-02] c9 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}