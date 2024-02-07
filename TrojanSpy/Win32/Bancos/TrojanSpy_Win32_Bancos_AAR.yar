
rule TrojanSpy_Win32_Bancos_AAR{
	meta:
		description = "TrojanSpy:Win32/Bancos.AAR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b7 44 50 fe 03 45 90 01 01 b9 ff 00 00 00 99 f7 f9 89 55 90 01 01 8b 45 90 01 01 3b 45 90 01 01 7d 05 ff 45 90 01 01 eb 07 c7 45 90 01 01 01 00 00 00 8b 45 90 01 01 8b 55 90 01 01 0f b7 44 50 fe 31 45 90 00 } //01 00 
		$a_00_1 = {5c 00 62 00 6f 00 62 00 2e 00 74 00 78 00 74 00 } //01 00  \bob.txt
		$a_00_2 = {49 00 6e 00 65 00 74 00 55 00 52 00 4c 00 3a 00 2f 00 31 00 2e 00 30 00 } //01 00  InetURL:/1.0
		$a_00_3 = {45 00 61 00 73 00 79 00 50 00 61 00 67 00 6f 00 73 00 2e 00 41 00 63 00 74 00 75 00 61 00 6c 00 69 00 7a 00 61 00 45 00 73 00 74 00 61 00 64 00 6f 00 43 00 61 00 73 00 68 00 2f 00 70 00 6f 00 73 00 74 00 2e 00 61 00 73 00 70 00 } //00 00  EasyPagos.ActualizaEstadoCash/post.asp
	condition:
		any of ($a_*)
 
}