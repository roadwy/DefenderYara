
rule Trojan_Win32_TrickBot_DSW_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 3c 38 30 39 03 ce 03 fe eb 90 01 01 33 ff 3b ca 72 90 09 05 00 83 ff 90 01 01 7f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}