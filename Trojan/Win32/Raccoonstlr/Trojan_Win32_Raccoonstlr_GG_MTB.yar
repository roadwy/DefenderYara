
rule Trojan_Win32_Raccoonstlr_GG_MTB{
	meta:
		description = "Trojan:Win32/Raccoonstlr.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f3 33 75 90 02 02 2b fe 25 90 02 04 81 6d 90 02 05 bb 90 02 04 81 45 90 02 05 8b 4d 90 02 02 83 25 90 02 04 00 8b c7 d3 e0 8b cf c1 e9 90 02 02 03 4d 90 02 02 03 45 90 02 02 33 c1 8b 4d 90 02 02 03 cf 33 c1 90 02 20 8d 45 90 02 02 e8 90 02 04 ff 4d 90 02 02 0f 85 90 02 64 89 7e 90 02 02 5f 5e 5b c9 90 02 64 83 c6 90 02 02 4f 75 90 00 } //1
		$a_02_1 = {55 8b ec 51 a1 90 02 04 8b 15 90 02 04 89 45 90 02 02 b8 90 02 04 01 45 90 02 02 8b 45 90 02 02 8a 04 90 02 02 88 04 90 02 02 c9 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}