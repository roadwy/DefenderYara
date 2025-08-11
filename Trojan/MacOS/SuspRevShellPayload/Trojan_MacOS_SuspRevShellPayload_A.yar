
rule Trojan_MacOS_SuspRevShellPayload_A{
	meta:
		description = "Trojan:MacOS/SuspRevShellPayload.A,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {30 0c 80 d2 01 fe 46 d3 20 f8 7f d3 e2 03 1f aa e1 66 02 d4 e3 03 20 aa 01 42 80 d2 } //1
		$a_00_1 = {e0 f2 e1 83 1f f8 02 01 80 d2 e1 63 22 cb 02 02 80 d2 50 0c 80 d2 e1 66 02 d4 42 fc 42 d3 e0 03 23 aa 42 fc 41 d3 e1 03 02 aa } //1
		$a_00_2 = {50 0b 80 d2 e1 66 02 d4 ea 03 1f aa 5f 01 02 eb 21 ff ff 54 e1 45 8c d2 21 cd ad f2 e1 65 ce f2 01 0d e0 f2 e1 83 1f f8 01 01 80 } //1
		$a_00_3 = {d2 e0 63 21 cb e1 03 1f aa e2 03 1f aa 70 07 80 d2 e1 66 02 d4 } //1
		$a_00_4 = {5f 6d 65 6d 63 70 79 } //1 _memcpy
		$a_00_5 = {5f 6d 6d 61 70 } //1 _mmap
		$a_00_6 = {5f 6d 70 72 6f 74 65 63 74 } //1 _mprotect
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}