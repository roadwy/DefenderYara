
rule Trojan_WinNT_Adwind_YC_MTB{
	meta:
		description = "Trojan:WinNT/Adwind.YC!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 66 71 70 63 73 77 67 7a 71 6c 72 6b 71 3d } //1 pfqpcswgzqlrkq=
		$a_00_1 = {72 62 71 63 67 73 75 63 66 } //1 rbqcgsucf
		$a_00_2 = {75 61 65 66 71 67 72 66 3d } //1 uaefqgrf=
		$a_00_3 = {72 62 71 63 67 73 75 63 66 2f 24 2e 23 73 61 72 78 6f 61 68 7a 73 79 32 } //1 rbqcgsucf/$.#sarxoahzsy2
		$a_00_4 = {6e 79 6f 7a 6e 64 6f 67 7b 62 7a 63 6e 6b 6d 3d } //1 nyozndog{bzcnkm=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}