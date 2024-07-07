
rule Trojan_Win32_Ursnif_BV_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 f1 81 c7 90 01 04 8b c6 2b c3 89 7d 00 66 0f b6 1d 90 01 04 83 e8 90 01 01 66 3b d9 73 90 02 15 8d 84 00 90 01 04 0f b7 d2 2b c6 03 c2 83 c5 04 83 6c 24 10 90 01 01 0f 85 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}