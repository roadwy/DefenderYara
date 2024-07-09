
rule Trojan_Win32_Qbot_ND_MTB{
	meta:
		description = "Trojan:Win32/Qbot.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 7c 24 18 81 [0-05] 01 [0-05] 81 [0-07] 8b [0-03] 8b 17 90 18 0f [0-06] 2b c8 83 [0-02] 81 [0-05] 89 [0-05] 89 17 83 [0-02] 89 [0-05] 8b [0-05] 83 [0-02] 89 [0-03] 03 d0 ff [0-03] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}