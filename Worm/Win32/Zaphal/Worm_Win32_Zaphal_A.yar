
rule Worm_Win32_Zaphal_A{
	meta:
		description = "Worm:Win32/Zaphal.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 75 63 6b } //1 fuck
		$a_01_1 = {75 70 64 61 74 65 2e 70 68 70 3f } //1 update.php?
		$a_01_2 = {79 61 68 6f 6f 62 75 64 64 79 6d 61 69 6e } //1 yahoobuddymain
		$a_01_3 = {70 61 73 73 77 64 3d } //1 passwd=
		$a_01_4 = {26 68 5b 5d 3d 70 72 6f 66 69 6c 65 2e 7a 61 70 74 6f 2e 6f 72 67 26 69 70 3d } //1 &h[]=profile.zapto.org&ip=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}