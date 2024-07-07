
rule Trojan_Win32_Emotet_DDS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {57 6a 40 68 00 30 00 00 56 57 8b d8 ff 15 90 01 04 50 ff 15 90 01 04 8b f8 56 53 57 e8 90 01 04 8b 44 24 1c 83 c4 0c 90 00 } //1
		$a_02_1 = {bf 00 30 00 00 50 57 ff 75 d8 53 ff 55 c0 50 ff 55 c4 ff 75 d8 89 45 dc ff 75 bc 50 e8 90 01 04 83 c4 0c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}