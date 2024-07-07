
rule Trojan_Win32_Ursnif_AQ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c1 83 c0 90 01 01 99 a3 90 01 04 89 15 90 01 04 8b 54 24 90 01 01 69 c9 90 01 04 03 ce 66 89 0d 90 01 04 a1 90 01 04 8b c8 69 c0 90 01 04 69 c9 90 01 04 81 c5 90 01 04 89 2a 83 c2 04 ff 4c 24 90 01 01 8d 3c 03 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}