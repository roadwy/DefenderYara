
rule Trojan_MacOS_Leap_A_MTB{
	meta:
		description = "Trojan:MacOS/Leap.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 70 70 68 6f 6f 6b 2e 74 61 72 } //1 apphook.tar
		$a_00_1 = {6f 6f 6d 70 61 } //1 oompa
		$a_00_2 = {28 6b 4d 44 49 74 65 6d 4b 69 6e 64 20 3d 3d 20 27 41 70 70 6c 69 63 61 74 69 6f 6e 27 29 20 26 26 20 28 6b 4d 44 49 74 65 6d 4c 61 73 74 55 73 65 64 44 61 74 65 20 3e 3d 20 24 74 69 6d 65 2e 74 68 69 73 5f 6d 6f 6e 74 68 29 } //1 (kMDItemKind == 'Application') && (kMDItemLastUsedDate >= $time.this_month)
		$a_00_3 = {7c 00 e2 78 7c 1e 11 ae 38 42 00 01 7c 1e 10 ae 7c 00 07 74 2f 80 00 00 40 9e ff e8 38 21 00 50 7f c3 f3 78 80 01 00 08 bb 81 ff f0 7c 08 03 a6 4e 80 00 20 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}