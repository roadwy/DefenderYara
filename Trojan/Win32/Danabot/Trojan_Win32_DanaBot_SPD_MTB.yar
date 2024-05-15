
rule Trojan_Win32_DanaBot_SPD_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 10 30 04 0e 83 ff 0f } //00 00 
	condition:
		any of ($a_*)
 
}