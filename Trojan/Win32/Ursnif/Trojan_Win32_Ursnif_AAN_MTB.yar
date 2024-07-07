
rule Trojan_Win32_Ursnif_AAN_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 47 fc 83 c2 05 05 d0 b3 e6 01 8b f2 89 47 fc 2b 74 24 14 4e a3 90 01 04 ff 4c 24 10 75 90 00 } //1
		$a_02_1 = {8b c5 81 c1 f8 04 7c 01 2b c7 89 0a 83 e8 08 83 c2 04 0f af c5 89 54 24 14 69 c0 90 01 04 ff 4c 24 18 0f b7 f0 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}