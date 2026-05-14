
rule Trojan_Win64_Redcap_ARPA_MTB{
	meta:
		description = "Trojan:Win64/Redcap.ARPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 48 8b 8c 24 58 ac 00 00 48 89 8c 24 98 5c 01 00 0f b6 c8 48 8b 84 24 98 5c 01 00 8b 00 d3 f8 89 84 24 40 56 00 00 48 8d 0d 13 a1 01 00 ff 15 ?? ?? ?? ?? 48 8d 15 ee a0 01 00 48 8b c8 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}