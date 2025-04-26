
rule Trojan_Win32_Ursnif_DK_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 7d 10 00 8b 07 89 45 f8 74 04 85 c0 74 1c 33 45 fc 43 33 45 0c 8a cb d3 c8 8b 4d f8 83 c7 04 89 4d fc 89 06 83 c6 04 4a 75 } //4
		$a_01_1 = {8d 34 08 33 75 e8 68 00 30 00 00 33 75 ec 50 6a 00 83 c6 0e ff 15 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}