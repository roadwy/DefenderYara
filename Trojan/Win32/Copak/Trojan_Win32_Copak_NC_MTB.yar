
rule Trojan_Win32_Copak_NC_MTB{
	meta:
		description = "Trojan:Win32/Copak.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {41 4b 8b 3c 24 83 c4 04 81 ea 90 01 04 21 db 8b 34 24 90 00 } //03 00 
		$a_03_1 = {83 c4 04 e8 28 00 00 00 09 db 89 ca 8b 3c 24 83 c4 90 01 01 81 eb 01 00 00 00 5e 09 d3 21 db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Copak_NC_MTB_2{
	meta:
		description = "Trojan:Win32/Copak.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {8d 3c 3b 8b 3f 21 c0 81 e7 90 01 04 89 d0 43 42 21 c2 81 fb f4 01 00 00 75 05 90 00 } //03 00 
		$a_03_1 = {81 ee 45 af a2 a7 81 c3 90 01 04 db 81 c1 01 00 00 00 21 db 89 db 81 f9 f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Copak_NC_MTB_3{
	meta:
		description = "Trojan:Win32/Copak.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {e8 30 00 00 00 bf ee 4f eb e4 01 fe 31 03 81 ee 90 01 04 81 c6 64 92 78 96 81 c3 90 01 04 09 fe 39 d3 75 c8 90 00 } //05 00 
		$a_03_1 = {81 c2 01 00 00 00 81 eb 90 01 04 81 ef 40 6c dd 10 81 fa 90 01 04 75 05 ba 00 00 00 00 09 fb 81 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}