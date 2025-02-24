
rule Trojan_Win32_Vidar_LLV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.LLV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 ff 89 f0 89 fa 83 e2 03 8a 54 14 ?? 30 14 38 47 8b 44 24 04 8b 54 24 08 89 d6 29 c6 39 f7 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}