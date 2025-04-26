
rule PWS_Win32_Reteged_A{
	meta:
		description = "PWS:Win32/Reteged.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 69 70 2e 50 68 70 3f 55 73 65 72 4e 61 6d 65 3d 00 } //1
		$a_01_1 = {74 79 70 65 3d 31 26 70 72 6f 64 75 63 74 3d 75 72 73 26 75 73 65 72 6e 61 6d 65 3d 00 } //1
		$a_01_2 = {44 6c 6c 44 6f 77 6e 2f 45 78 65 2e 44 6c 6c 00 } //1
		$a_01_3 = {26 42 61 6e 6b 3d 41 6c 69 50 61 79 26 4d 6f 6e 65 79 3d } //1 &Bank=AliPay&Money=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}