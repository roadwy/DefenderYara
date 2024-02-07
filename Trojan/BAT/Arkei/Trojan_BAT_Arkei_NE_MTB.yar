
rule Trojan_BAT_Arkei_NE_MTB{
	meta:
		description = "Trojan:BAT/Arkei.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 72 01 00 00 70 0a 72 90 01 01 00 00 70 0b 28 01 00 00 06 0c 08 16 28 02 00 00 06 26 73 0f 00 00 0a 0d 09 06 07 6f 10 00 00 0a 00 20 dc 05 00 00 28 11 00 00 0a 00 00 00 20 b3 15 00 00 28 11 00 00 0a 00 28 04 00 00 06 00 2a 90 00 } //01 00 
		$a_01_1 = {2f 00 43 00 73 00 74 00 61 00 72 00 74 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 } //01 00  /Cstart C:\Windows\Temp\
		$a_01_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //00 00  cmd.exe
	condition:
		any of ($a_*)
 
}