
rule Trojan_Win32_ZLoader_RZ_MTB{
	meta:
		description = "Trojan:Win32/ZLoader.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 61 6e 67 65 72 5c 66 69 74 5c 53 68 65 6c 6c 5c 46 61 72 5c 57 6f 6d 65 6e 5c 64 65 61 6c 5c 66 69 72 65 2e 70 64 62 } //1 c:\anger\fit\Shell\Far\Women\deal\fire.pdb
		$a_01_1 = {66 69 72 65 2e 64 6c 6c } //1 fire.dll
		$a_01_2 = {43 68 69 65 66 } //1 Chief
		$a_01_3 = {72 70 72 2f 64 6e 75 38 69 74 65 63 70 6f 36 20 63 6e 76 6d 72 6c 6e 45 6e 6f } //1 rpr/dnu8itecpo6 cnvmrlnEno
		$a_01_4 = {68 36 30 6f 65 64 56 69 64 6d 72 33 2f 77 20 69 69 52 35 64 6e 36 72 6e 6c 53 56 6f 65 79 6d 6f 20 62 72 53 } //1 h60oedVidmr3/w iiR5dn6rnlSVoeymo brS
		$a_01_5 = {6f 6e 63 63 33 75 36 31 30 72 65 61 20 69 65 78 69 6d 35 77 6d 65 72 31 6f 20 30 64 61 57 69 2e 4d 30 6b 69 62 69 } //1 oncc3u610rea iexim5wmer1o 0daWi.M0kibi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}