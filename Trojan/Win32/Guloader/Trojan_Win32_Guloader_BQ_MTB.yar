
rule Trojan_Win32_Guloader_BQ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 6f 6e 69 63 61 74 6f 72 73 5c 66 61 6c 73 69 66 69 6b 61 74 69 6f 6e 65 6e 5c 64 65 63 61 6c 5c 6c 65 63 74 69 63 61 2e 6f 65 64 } //1 sonicators\falsifikationen\decal\lectica.oed
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 73 6f 6c 73 6b 69 6e 73 74 61 67 65 5c 6f 76 65 72 73 65 72 65 6e 65 } //1 Software\Microsoft\Windows\CurrentVersion\Uninstall\solskinstage\overserene
		$a_01_2 = {73 6f 6c 65 6e 6f 73 74 6f 6d 69 64 5c 74 65 6c 65 73 61 74 65 6c 6c 69 74 74 65 72 73 2e 43 6f 70 } //1 solenostomid\telesatellitters.Cop
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 42 79 73 76 61 6c 65 72 6e 65 5c 70 72 65 75 6e 64 65 72 73 74 61 6e 64 69 6e 67 } //1 Software\Bysvalerne\preunderstanding
		$a_01_4 = {72 65 71 75 69 73 69 74 69 6f 6e 65 64 5c 61 72 69 74 6d 65 74 69 6b 65 72 5c 61 6e 74 69 74 75 6d 6f 75 72 5c 62 69 6c 61 74 65 72 61 6c 2e 69 6e 69 } //1 requisitioned\aritmetiker\antitumour\bilateral.ini
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}