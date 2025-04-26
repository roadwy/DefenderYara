
rule Trojan_Win32_Qbot_NA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a c3 2c 09 02 c2 90 18 0f [0-02] 8b ?? 2b ?? 0f [0-02] 2b ?? 89 [0-03] 8b [0-03] 89 [0-05] 8b [0-03] 8a e2 80 ec 09 8b 3f 02 e0 3b ce 90 18 8a ca 81 [0-05] 2a cb 89 [0-05] 80 [0-02] 02 c1 8b [0-03] 83 [0-04] 89 39 8b [0-05] 8b [0-04] 69 [0-05] 83 [0-04] 0f [0-02] 89 [0-03] 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}