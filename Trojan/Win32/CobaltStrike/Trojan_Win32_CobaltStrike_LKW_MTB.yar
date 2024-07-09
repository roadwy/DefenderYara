
rule Trojan_Win32_CobaltStrike_LKW_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.LKW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d7 8b 45 ?? 83 e7 ?? 8a 04 38 30 04 0a 42 83 fa ?? 75 ec } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}