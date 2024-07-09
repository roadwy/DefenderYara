
rule Trojan_Win32_Bandit_YP_MTB{
	meta:
		description = "Trojan:Win32/Bandit.YP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 18 81 c6 47 86 c8 61 ff 4c 24 1c 8b 4c 24 14 ?? ?? ?? ?? ?? ?? 8b 74 24 2c 89 3e 81 fa 6d 0a 00 00 75 90 09 06 00 8b 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}