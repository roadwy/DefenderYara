
rule Trojan_Win32_Emotet_MG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 10 00 00 [0-03] 51 6a 00 ff 55 ?? 89 [0-02] 8b [0-03] 8b [0-02] 50 8b [0-03] ff [0-02] 83 ?? 0c 8b [0-03] 8d [0-02] 50 8b [0-03] 6a 00 6a 01 6a 00 8b 55 ?? 52 ff 55 ?? 85 c0 [0-02] 33 c0 eb [0-c8] 83 c4 0c 89 [0-02] 8b [0-02] 89 [0-02] ff 55 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}