
rule Trojan_Win32_Lotok_A_MTB{
	meta:
		description = "Trojan:Win32/Lotok.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 8b f8 66 c7 44 24 14 02 00 ff 15 ?? ?? ?? ?? 66 89 44 24 12 8b 47 0c 6a 10 8b 08 8d 44 24 14 50 8b 11 8b 4e 08 51 89 54 24 20 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}