
rule Trojan_Win32_Copak_DS_MTB{
	meta:
		description = "Trojan:Win32/Copak.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 e9 ed b4 1e 4e 31 30 81 e9 01 00 00 00 40 83 ec 04 89 3c 24 5f 01 ff 39 d0 75 } //02 00 
		$a_01_1 = {8b 14 24 83 c4 04 8b 34 24 83 c4 04 09 c0 4a 81 e8 24 0e aa b8 47 21 d2 81 ff 4a e1 00 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}