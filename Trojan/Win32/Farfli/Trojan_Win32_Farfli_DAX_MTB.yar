
rule Trojan_Win32_Farfli_DAX_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 10 6a 00 8b 56 04 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a ff 51 6a ff 52 8b f8 ff 15 } //01 00 
		$a_01_1 = {8b d8 b9 00 00 04 00 b8 2a 2a 2a 2a 8b fb f3 ab 83 c4 04 bf 13 00 00 00 8d 55 f8 6a 00 52 53 ff 15 } //01 00 
		$a_01_2 = {72 6f 73 73 65 63 6f 72 50 6c 61 72 74 6e 65 43 5c 6d 65 74 73 79 53 5c 4e 4f 49 54 50 49 52 43 53 45 44 5c 45 52 41 57 44 52 41 48 } //01 00  rossecorPlartneC\metsyS\NOITPIRCSED\ERAWDRAH
		$a_01_3 = {6f 70 6a 6b 72 6f 70 69 6f 69 61 73 64 6a 61 69 65 65 65 } //01 00  opjkropioiasdjaieee
		$a_01_4 = {69 6e 64 65 78 5b 33 5d 2e 74 78 74 } //00 00  index[3].txt
	condition:
		any of ($a_*)
 
}