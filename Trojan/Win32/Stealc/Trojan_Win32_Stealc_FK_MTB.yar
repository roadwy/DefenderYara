
rule Trojan_Win32_Stealc_FK_MTB{
	meta:
		description = "Trojan:Win32/Stealc.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 44 24 ?? 83 c0 64 89 44 24 ?? 83 6c 24 ?? 64 8a 4c 24 ?? 30 0c 3e 46 3b f3 } //3
		$a_01_1 = {6d 65 79 6f 6c 75 7a 69 68 65 20 79 65 79 6f 62 69 73 } //1 meyoluzihe yeyobis
		$a_01_2 = {6c 00 6f 00 76 00 6f 00 78 00 6f 00 64 00 61 00 7a 00 75 00 66 00 } //1 lovoxodazuf
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}