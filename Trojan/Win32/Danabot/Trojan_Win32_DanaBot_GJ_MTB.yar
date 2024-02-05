
rule Trojan_Win32_DanaBot_GJ_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 18 88 10 88 1e 0f b6 00 0f b6 d3 03 c2 23 c1 90 02 25 8a 80 90 02 30 33 cd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}