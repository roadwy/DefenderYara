
rule Trojan_Win32_RanumBot_MU_MTB{
	meta:
		description = "Trojan:Win32/RanumBot.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 45 ec 83 [0-06] 90 18 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 33 [0-02] 89 [0-02] 8b [0-02] 29 [0-02] 8b [0-02] 2b [0-02] 89 [0-02] e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}