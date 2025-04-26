
rule Backdoor_Win32_Saluchtra_B_dha{
	meta:
		description = "Backdoor:Win32/Saluchtra.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 70 68 70 3f 63 6f 6d 70 6e 61 6d 65 3d } //1 .php?compname=
		$a_01_1 = {2f 63 20 77 6d 69 63 20 64 69 73 6b 64 72 69 76 65 20 6c 69 73 74 20 62 72 69 65 66 20 3e 20 } //1 /c wmic diskdrive list brief > 
		$a_01_2 = {5c 70 65 72 63 66 30 30 31 2e 64 61 74 } //1 \percf001.dat
		$a_01_3 = {56 42 4f 58 00 00 00 00 56 4d 77 61 72 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}