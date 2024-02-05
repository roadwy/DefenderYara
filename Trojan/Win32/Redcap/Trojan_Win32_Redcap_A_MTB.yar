
rule Trojan_Win32_Redcap_A_MTB{
	meta:
		description = "Trojan:Win32/Redcap.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b ca 2b cf f7 df 8b 09 89 4e 08 8b 54 3a fc 8b fa 2b f9 89 7e 0c 76 1b 33 ff 33 f6 46 83 ff 15 7f 0b 8a 1c 38 03 fe 30 19 03 ce eb 02 33 ff 3b ca 72 ea 33 c0 5e 5f 5b c2 } //00 00 
	condition:
		any of ($a_*)
 
}