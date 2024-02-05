
rule Trojan_Win32_LokiBot_RDJ_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b6 55 fe c1 fa 05 0f b6 45 fe c1 e0 03 0b d0 } //00 00 
	condition:
		any of ($a_*)
 
}