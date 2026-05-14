
rule Trojan_Win32_Androm_BAN_MTB{
	meta:
		description = "Trojan:Win32/Androm.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c2 83 c0 04 89 45 ?? ff 75 ?? b9 d6 85 00 00 b9 d6 85 00 00 b9 d6 85 00 00 b9 d6 85 00 00 b9 d6 85 00 00 b9 d6 85 00 00 ff 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Androm_BAN_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c2 83 c0 04 89 45 ?? ff 75 ?? b9 c8 18 00 00 b9 c8 18 00 00 b9 c8 18 00 00 b9 c8 18 00 00 b9 c8 18 00 00 b9 c8 18 00 00 ff 75 ?? b9 c8 18 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}