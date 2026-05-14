
rule Backdoor_Win32_SuspNtdsAccess_C_genA{
	meta:
		description = "Backdoor:Win32/SuspNtdsAccess.C!genA,SIGNATURE_TYPE_CMDHSTR_EXT,32 00 32 00 06 00 00 "
		
	strings :
		$a_00_0 = {5c 00 65 00 73 00 65 00 6e 00 74 00 75 00 74 00 6c 00 2e 00 65 00 78 00 65 00 } //10 \esentutl.exe
		$a_00_1 = {2f 00 76 00 73 00 73 00 } //10 /vss
		$a_00_2 = {2f 00 79 00 20 00 } //10 /y 
		$a_00_3 = {63 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 6e 00 74 00 64 00 73 00 } //10 c:\windows\ntds
		$a_00_4 = {2f 00 64 00 20 00 63 00 3a 00 5c 00 } //10 /d c:\
		$a_00_5 = {3a 00 5c 00 69 00 66 00 6d 00 } //-200 :\ifm
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*-200) >=50
 
}