
rule Trojan_Win32_Emotet_LG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.LG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 10 00 00 [0-04] 6a 00 ff [0-03] ff [0-03] 89 44 [0-02] ff [0-03] 50 ff 54 [0-02] 83 c4 ?? ff [0-03] 8d 44 [0-02] 50 ff [0-03] 6a 00 6a 01 6a 00 ff 74 [0-02] ff 54 [0-02] 85 c0 [0-06] 8b 44 [0-02] 5f 5e 5d 5b 83 c4 ?? c3 [0-50] 83 c4 ?? ff d0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}