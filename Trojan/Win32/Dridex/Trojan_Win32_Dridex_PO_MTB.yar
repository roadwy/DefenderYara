
rule Trojan_Win32_Dridex_PO_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 18 8b [0-03] ba [0-04] f7 ?? 69 [0-05] 01 ?? 89 [0-03] 89 [0-03] 8b [0-03] 83 [0-02] 89 [0-03] 8b [0-03] 8b [0-02] 8b [0-03] 2b [0-03] 89 [0-03] 80 [0-03] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}