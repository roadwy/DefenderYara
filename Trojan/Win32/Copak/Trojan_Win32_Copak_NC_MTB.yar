
rule Trojan_Win32_Copak_NC_MTB{
	meta:
		description = "Trojan:Win32/Copak.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {e8 30 00 00 00 bf ee 4f eb e4 01 fe 31 03 81 ee 90 01 04 81 c6 64 92 78 96 81 c3 90 01 04 09 fe 39 d3 75 c8 90 00 } //05 00 
		$a_03_1 = {81 c2 01 00 00 00 81 eb 90 01 04 81 ef 40 6c dd 10 81 fa 90 01 04 75 05 ba 00 00 00 00 09 fb 81 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}