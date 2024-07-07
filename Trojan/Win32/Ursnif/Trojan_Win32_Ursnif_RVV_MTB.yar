
rule Trojan_Win32_Ursnif_RVV_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 74 24 10 05 34 a3 98 01 89 06 a3 90 01 04 0f b7 c5 39 05 90 01 04 72 90 00 } //1
		$a_02_1 = {8b 7c 24 28 b8 fd ff 00 00 2b c3 2b 44 24 18 66 03 f0 8b 44 24 24 05 ec 65 f5 01 66 89 35 90 01 04 89 07 bf ca ff 00 00 89 44 24 24 a3 90 01 04 b8 a2 20 00 00 66 39 05 90 01 04 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}