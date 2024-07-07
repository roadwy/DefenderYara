
rule PWS_Win64_Dyzap_A{
	meta:
		description = "PWS:Win64/Dyzap.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 44 59 52 45 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 64 79 72 65 63 6f 6e 74 72 6f 6c 6c 65 72 2e 70 64 62 } //1 \DYRE\x64\Release\dyrecontroller.pdb
		$a_00_1 = {5c 00 5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 52 00 61 00 6e 00 67 00 69 00 73 00 50 00 69 00 70 00 65 00 } //1 \\.\pipe\RangisPipe
		$a_00_2 = {2f 25 73 2f 25 73 2f 35 2f 70 75 62 6c 69 63 6b 65 79 2f } //1 /%s/%s/5/publickey/
		$a_01_3 = {64 00 65 00 66 00 63 00 6f 00 6e 00 66 00 69 00 67 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}