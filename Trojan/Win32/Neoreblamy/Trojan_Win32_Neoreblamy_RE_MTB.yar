
rule Trojan_Win32_Neoreblamy_RE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 8b 14 01 83 c2 01 6b 45 f4 74 8b 4d fc 89 14 01 6b 55 f4 74 8b 45 fc 8b 0c 10 83 e9 01 6b 55 f4 74 8b 45 fc 89 4c 10 08 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}