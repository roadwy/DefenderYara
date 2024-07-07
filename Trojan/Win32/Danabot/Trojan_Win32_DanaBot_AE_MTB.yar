
rule Trojan_Win32_DanaBot_AE_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 33 ce c1 e8 90 01 01 03 44 24 90 01 01 89 44 24 90 01 01 89 4c 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 2b 5c 24 90 01 01 8b 44 24 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}