
rule Trojan_Win32_Medphar_A{
	meta:
		description = "Trojan:Win32/Medphar.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 71 2d 70 68 61 72 6d 61 2e 6f 72 67 2f 5f 69 64 5f } //01 00  hq-pharma.org/_id_
		$a_01_1 = {64 72 69 76 65 72 73 5c 73 79 73 74 65 6d 2e 65 78 65 20 25 } //01 00  drivers\system.exe %
		$a_03_2 = {99 33 c2 2b c2 83 c0 17 8d 90 01 02 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}