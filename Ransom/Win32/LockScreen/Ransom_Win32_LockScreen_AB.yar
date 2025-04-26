
rule Ransom_Win32_LockScreen_AB{
	meta:
		description = "Ransom:Win32/LockScreen.AB,SIGNATURE_TYPE_PEHSTR,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 6c 41 20 6d 45 20 6b 63 6f 4c } //1 llA mE kcoL
		$a_01_1 = {65 00 78 00 65 00 2e 00 74 00 69 00 6e 00 69 00 72 00 65 00 73 00 75 00 5c 00 } //1 exe.tiniresu\
		$a_01_2 = {65 78 65 2e 72 65 72 6f 6c 70 78 65 } //1 exe.rerolpxe
		$a_01_3 = {65 64 6f 6d 20 53 4f 44 20 6e 69 20 6e 75 72 20 65 62 20 74 6f 6e 6e 61 63 20 6d 61 72 67 6f 72 70 20 73 69 68 54 } //1 edom SOD ni nur eb tonnac margorp sihT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}