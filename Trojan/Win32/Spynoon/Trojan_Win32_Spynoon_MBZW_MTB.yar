
rule Trojan_Win32_Spynoon_MBZW_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.MBZW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 eb fc 00 0f 20 00 33 44 54 65 } //01 00 
		$a_01_1 = {49 d8 46 00 6c 16 40 00 10 f0 30 00 00 ff ff ff 08 } //00 00 
	condition:
		any of ($a_*)
 
}