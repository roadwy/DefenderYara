
rule Trojan_Win32_Ursnif_RAR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b7 d3 b8 4c 00 00 00 2b c2 8b 15 90 01 04 2b c1 03 f0 81 c7 4c d4 25 01 89 35 90 00 } //1
		$a_02_1 = {81 ea fa 43 00 00 0f b7 da 0f b7 cb 83 c6 04 81 fe ff 08 00 00 8d 84 08 90 01 04 a3 90 01 04 0f 82 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}