
rule Trojan_Win64_IcedID_BB_MSR{
	meta:
		description = "Trojan:Win64/IcedID.BB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 46 73 4b 56 71 } //02 00  BFsKVq
		$a_01_1 = {42 67 47 45 50 53 } //02 00  BgGEPS
		$a_01_2 = {46 76 68 6e 72 68 45 46 56 } //02 00  FvhnrhEFV
		$a_01_3 = {47 68 6e 6a 68 62 64 61 67 62 68 69 61 73 64 6c 6b 73 61 } //02 00  Ghnjhbdagbhiasdlksa
		$a_01_4 = {4e 41 6e 5a 4b 45 76 } //02 00  NAnZKEv
		$a_01_5 = {4f 41 57 68 68 6e 52 4b 41 46 4a } //02 00  OAWhhnRKAFJ
		$a_01_6 = {52 51 46 4f 6c 41 } //02 00  RQFOlA
		$a_01_7 = {56 47 67 50 7a 4e 6f 68 6d } //02 00  VGgPzNohm
		$a_01_8 = {58 63 4c 69 6a 5a 5a 77 62 } //02 00  XcLijZZwb
		$a_01_9 = {61 4c 5a 41 59 4d 5a 76 51 } //00 00  aLZAYMZvQ
	condition:
		any of ($a_*)
 
}