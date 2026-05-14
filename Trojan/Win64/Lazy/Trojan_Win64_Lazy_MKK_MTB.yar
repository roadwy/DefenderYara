
rule Trojan_Win64_Lazy_MKK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 20 6d 61 6c 77 61 72 65 } //10 load malware
		$a_01_1 = {61 6c 6c 20 6d 61 6c 77 61 72 65 20 70 61 74 63 68 65 73 20 73 68 6f 75 6c 64 20 62 65 20 6e 6f 77 20 76 69 73 69 62 6c 65 } //5 all malware patches should be now visible
		$a_01_2 = {6c 6f 61 64 20 77 69 6e 64 6f 77 73 20 77 69 74 68 6f 75 74 20 6d 61 6c 77 61 72 65 } //3 load windows without malware
		$a_01_3 = {64 75 6d 70 20 74 61 72 67 65 74 20 70 72 6f 63 65 73 73 20 6d 6f 64 75 6c 65 73 20 74 6f 20 64 69 73 6b } //2 dump target process modules to disk
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=20
 
}