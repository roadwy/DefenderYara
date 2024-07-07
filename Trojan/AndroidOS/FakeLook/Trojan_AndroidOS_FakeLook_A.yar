
rule Trojan_AndroidOS_FakeLook_A{
	meta:
		description = "Trojan:AndroidOS/FakeLook.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 6d 61 6e 2d 69 6e 2d 74 68 65 2d 6d 69 64 64 6c 65 20 61 74 74 61 63 6b 29 21 } //1 (man-in-the-middle attack)!
		$a_01_1 = {5f 61 63 6b 69 64 3d } //1 _ackid=
		$a_01_2 = {53 4f 4d 45 54 48 49 4e 47 20 4e 41 53 54 59 21 } //1 SOMETHING NASTY!
		$a_01_3 = {68 74 74 70 3a 2f 2f 74 68 65 6c 6f 6e 67 69 73 6c 61 6e 64 70 72 65 73 73 2e 63 6f 6d 2f 63 6f 6e 74 72 6f 6c 73 2e 70 68 70 00 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*3) >=5
 
}