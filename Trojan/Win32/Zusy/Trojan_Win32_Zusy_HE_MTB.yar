
rule Trojan_Win32_Zusy_HE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.HE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 70 61 79 6c 6f 61 64 2e 65 78 65 00 } //10
		$a_03_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-15] 00 6f 70 65 6e 00 00 90 04 ff 0b 61 2d 7a 41 2d 5a 30 2d 39 2b 2f } //50
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*50) >=60
 
}