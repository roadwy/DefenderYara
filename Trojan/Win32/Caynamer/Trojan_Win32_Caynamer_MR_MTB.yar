
rule Trojan_Win32_Caynamer_MR_MTB{
	meta:
		description = "Trojan:Win32/Caynamer.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d8 85 40 00 [0-02] e8 [0-0e] 31 [0-03] 81 [0-0c] 09 ?? 39 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}