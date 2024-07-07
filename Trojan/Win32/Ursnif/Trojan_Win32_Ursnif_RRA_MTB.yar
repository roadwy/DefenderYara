
rule Trojan_Win32_Ursnif_RRA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b9 15 1f 00 00 66 39 4c 24 0c 8d 46 06 8b 4c 24 18 66 a3 90 01 04 75 90 00 } //1
		$a_00_1 = {83 c1 04 89 4c 24 18 81 f9 a6 1e 00 00 0f 82 98 fe ff ff } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}