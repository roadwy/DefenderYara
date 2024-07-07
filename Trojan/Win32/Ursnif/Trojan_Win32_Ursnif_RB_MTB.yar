
rule Trojan_Win32_Ursnif_RB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 02 89 90 01 01 24 90 01 01 85 c9 74 1b 8b 10 2b 54 24 90 01 01 8b 90 01 01 24 90 01 01 01 54 24 90 01 01 83 44 24 90 01 02 83 c0 90 01 01 49 89 90 01 01 75 e5 8b 4e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}