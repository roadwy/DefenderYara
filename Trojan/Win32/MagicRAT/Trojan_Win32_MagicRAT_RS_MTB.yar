
rule Trojan_Win32_MagicRAT_RS_MTB{
	meta:
		description = "Trojan:Win32/MagicRAT.RS!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 00 61 00 67 00 69 00 63 00 4d 00 6f 00 6e 00 5c 00 4d 00 61 00 67 00 69 00 63 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 69 00 6e 00 69 00 } //1 MagicMon\MagicSystem.ini
		$a_01_1 = {76 00 65 00 72 00 79 00 76 00 65 00 72 00 75 00 6e 00 69 00 71 00 75 00 65 00 6b 00 65 00 79 00 } //1 veryveruniquekey
		$a_01_2 = {75 00 42 00 61 00 74 00 6b 00 42 00 6f 00 70 00 6f 00 42 00 72 00 61 00 68 00 } //1 uBatkBopoBrah
		$a_01_3 = {4c 30 46 77 63 45 52 68 64 47 45 76 55 6d 39 68 62 57 } //1 L0FwcERhdGEvUm9hbW
		$a_01_4 = {73 75 63 63 65 73 73 20 73 65 6c 66 20 64 65 6c 65 74 65 } //1 success self delete
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}