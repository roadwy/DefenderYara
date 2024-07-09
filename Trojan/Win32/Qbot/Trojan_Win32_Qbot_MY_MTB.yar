
rule Trojan_Win32_Qbot_MY_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {d3 c0 8a fc 8a e6 d3 cb ff [0-04] 57 33 [0-02] 09 ?? 83 [0-02] 09 ?? 5f 81 [0-05] 33 [0-02] 83 [0-02] aa 49 75 } //1
		$a_02_1 = {d3 c0 8a fc 8a e6 d3 cb ff [0-05] 8f [0-02] ff [0-02] 58 81 [0-05] 33 [0-02] 83 [0-02] aa 49 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}