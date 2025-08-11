
rule Trojan_MacOS_SuspRevShellPayload_P1{
	meta:
		description = "Trojan:MacOS/SuspRevShellPayload.P1,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {61 ac 8e d2 81 2d ac f2 81 ee cd f2 41 ce e5 f2 e1 03 1f f8 21 ed 8d d2 c1 6d ae f2 e1 65 c8 f2 21 8c ed f2 e1 83 1e f8 21 08 8e d2 01 8e ad f2 21 6d cc f2 21 8c ee f2 } //1
		$a_00_1 = {e1 e5 8d d2 01 ae ac f2 c1 0d c0 f2 e1 03 1d f8 e1 a5 8e d2 61 4e ae f2 e1 45 cc f2 21 cd ed f2 } //1
		$a_00_2 = {01 07 80 d2 e1 63 21 cb e1 03 1b f8 e0 03 01 aa e1 43 01 d1 e2 03 1f aa 70 07 80 d2 e1 66 02 d4 } //1
		$a_00_3 = {5f 6d 65 6d 63 70 79 } //1 _memcpy
		$a_00_4 = {5f 6d 6d 61 70 } //1 _mmap
		$a_00_5 = {5f 6d 70 72 6f 74 65 63 74 } //1 _mprotect
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}