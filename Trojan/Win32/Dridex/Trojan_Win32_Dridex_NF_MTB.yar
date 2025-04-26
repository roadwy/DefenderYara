
rule Trojan_Win32_Dridex_NF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 33 [0-06] c7 05 [0-08] 8b [0-06] 01 [0-06] 8b [0-06] 8b [0-06] 89 [0-06] 8b [0-06] 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}