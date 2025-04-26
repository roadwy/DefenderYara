
rule Trojan_Win32_Emotet_MIU_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 0c 1e 25 ff 00 00 00 8a 04 02 88 6c 24 5f 30 c8 8b 54 24 40 31 d2 89 54 24 60 8b 54 24 ?? 88 04 1a 01 fb 8b 7c 24 10 89 7c 24 4c 89 5c 24 54 8b 44 24 04 89 44 24 48 8b 44 24 44 39 c3 0f 84 a6 } //5
		$a_03_1 = {89 44 24 34 8b 84 24 a8 00 00 00 35 c9 47 bb 4e 89 44 24 30 8b 44 24 38 88 0c 06 8b 74 24 ?? 89 34 24 89 7c 24 04 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}