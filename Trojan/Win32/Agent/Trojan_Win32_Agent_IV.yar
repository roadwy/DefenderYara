
rule Trojan_Win32_Agent_IV{
	meta:
		description = "Trojan:Win32/Agent.IV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 68 30 63 6f 6c 61 74 } //01 00  ch0colat
		$a_01_1 = {6c 6f 73 20 68 6f 6d 62 72 33 73 47 47 } //01 00  los hombr3sGG
		$a_00_2 = {43 00 3a 00 5c 00 63 00 68 00 6f 00 63 00 6f 00 5c 00 6c 00 61 00 74 00 65 00 2d 00 70 00 31 00 65 00 6c 00 63 00 65 00 6c 00 65 00 73 00 74 00 69 00 61 00 5c 00 6c 00 2d 00 69 00 6e 00 64 00 65 00 54 00 65 00 2e 00 44 00 45 00 4d 00 } //00 00  C:\choco\late-p1elcelestia\l-indeTe.DEM
	condition:
		any of ($a_*)
 
}