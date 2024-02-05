
rule Trojan_Win32_GuLoader_RPG_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0b 1c 3a 83 90 02 10 81 f3 90 02 10 09 1c 38 90 02 10 83 ef 90 02 10 81 ff 90 02 10 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}