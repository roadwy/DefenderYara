
rule Trojan_Win64_XMRig_RK_MTB{
	meta:
		description = "Trojan:Win64/XMRig.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 4c 04 3e 48 ff c0 48 83 f8 0c 73 06 8a 4c 24 3d } //3
		$a_01_1 = {50 7a 4c 46 62 6d 42 6d 59 56 5a 58 62 6a 64 32 6d 73 39 34 64 4d 70 6f 56 57 35 6a 5a 6d 46 57 45 32 34 33 64 6d 55 77 65 48 52 79 61 46 56 75 59 32 5a } //2 PzLFbmBmYVZXbjd2ms94dMpoVW5jZmFWE243dmUweHRyaFVuY2Z
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}