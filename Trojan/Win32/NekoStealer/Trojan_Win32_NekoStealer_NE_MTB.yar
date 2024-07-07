
rule Trojan_Win32_NekoStealer_NE_MTB{
	meta:
		description = "Trojan:Win32/NekoStealer.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 61 79 69 20 77 65 76 75 78 69 72 61 20 62 6f 74 6f 74 61 6a 69 6b 61 73 69 78 65 76 20 77 61 77 65 } //1 Bayi wevuxira bototajikasixev wawe
		$a_01_1 = {67 69 63 75 70 6f 64 } //1 gicupod
		$a_01_2 = {54 65 74 6f 79 61 77 6f 6d 65 6c 6f 62 } //1 Tetoyawomelob
		$a_01_3 = {79 6f 72 75 6a 65 70 65 6e 75 76 61 62 75 } //1 yorujepenuvabu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}