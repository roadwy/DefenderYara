
rule Trojan_Win32_DanaBot_GF_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 30 04 31 b8 90 01 04 83 f0 90 01 01 83 6d 90 02 10 83 7d 90 02 10 0f 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}