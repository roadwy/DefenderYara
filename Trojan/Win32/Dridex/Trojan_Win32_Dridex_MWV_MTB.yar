
rule Trojan_Win32_Dridex_MWV_MTB{
	meta:
		description = "Trojan:Win32/Dridex.MWV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d7 8b 54 24 34 8b 74 24 10 29 f2 89 54 24 58 89 7c 24 38 35 3a ce 26 18 09 c8 c7 44 24 ?? ad 85 92 7a 89 44 24 04 74 b0 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}