
rule Trojan_Win64_Dridex_PV_MTB{
	meta:
		description = "Trojan:Win64/Dridex.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 44 24 47 24 ?? 88 [0-06] 8b [0-06] 48 8b [0-03] 48 83 [0-02] 48 89 [0-06] 81 [0-05] 48 8b [0-08] 2a [0-03] 48 8b [0-03] 4c 8b [0-03] 41 88 [0-02] 03 [0-06] 89 [0-06] 8a [0-05] 88 [0-06] 44 8b [0-05] c9 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}