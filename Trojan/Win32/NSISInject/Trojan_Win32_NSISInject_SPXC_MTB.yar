
rule Trojan_Win32_NSISInject_SPXC_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SPXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 61 6e 6e 65 72 2e 73 6c 76 } //01 00 
		$a_01_1 = {6b 6c 6f 6e 65 64 65 2e 74 69 74 } //01 00 
		$a_01_2 = {63 69 6c 69 6f 6c 75 6d 2e 64 6c 6c } //01 00 
		$a_01_3 = {6c 61 69 74 61 6e 63 65 73 5c 6c 65 67 61 74 2e 69 6e 69 } //01 00 
		$a_01_4 = {73 63 6f 6c 69 69 64 61 65 5c 52 6f 73 65 6e 72 64 2e 6c 6e 6b } //01 00 
		$a_01_5 = {63 6f 6d 62 69 6e 65 72 73 5c 67 61 6c 61 6e 74 65 72 69 65 72 5c 6c 65 64 65 6c 73 65 73 70 6c 61 6e 65 72 5c 73 6f 72 64 2e 44 72 61 33 33 } //01 00 
		$a_01_6 = {6e 75 6d 69 6e 61 5c 63 68 6c 6f 72 6f 70 6c 61 74 69 6e 6f 75 73 5c 52 65 62 65 6e 65 73 5c 66 72 65 6d 66 72 65 6c 73 65 2e 65 76 65 } //00 00 
	condition:
		any of ($a_*)
 
}