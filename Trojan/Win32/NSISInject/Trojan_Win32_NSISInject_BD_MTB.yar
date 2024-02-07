
rule Trojan_Win32_NSISInject_BD_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 54 72 6f 63 68 61 6e 74 65 72 61 6c 5c 45 6c 65 67 69 73 65 73 5c 54 6f 74 61 6c 61 66 68 6f 6c 64 65 6e 64 65 } //01 00  Software\Trochanteral\Elegises\Totalafholdende
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 45 6a 76 69 6e 73 5c 56 69 64 65 6f 63 61 73 74 5c 6f 76 65 72 65 6b 73 70 6f 6e 65 72 65 64 65 73 } //01 00  Software\Ejvins\Videocast\overeksponeredes
		$a_01_2 = {42 65 73 6b 79 64 6e 69 6e 67 65 72 6e 65 73 2e 56 69 73 } //01 00  Beskydningernes.Vis
		$a_01_3 = {49 6e 64 75 63 74 6f 70 68 6f 6e 65 2e 69 6e 69 } //00 00  Inductophone.ini
	condition:
		any of ($a_*)
 
}