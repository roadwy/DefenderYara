
rule Trojan_Win32_Grandoreiro_psyL_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 1c 57 8b fa 8b c1 2b f9 89 75 08 ?? ?? ?? 07 89 10 83 c0 04 ff 4d 08 75 f3 8b 55 fc 5f 03 f6 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}