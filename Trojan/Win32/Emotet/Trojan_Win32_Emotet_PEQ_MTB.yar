
rule Trojan_Win32_Emotet_PEQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {4a 81 ca 00 ff ff ff 42 8a 4c 14 ?? 8b 54 24 ?? 32 0c 1a 8b 44 24 ?? 88 0b } //1
		$a_81_1 = {50 68 7d 75 24 7c 38 72 76 43 73 77 38 37 33 7e 64 6b 42 66 3f 49 4d 3f 76 75 5a 54 6c 6a 56 74 59 42 4e 6d 41 58 5a 36 25 6c 7c 44 57 48 48 71 56 6f 74 44 66 78 51 53 4a 6e 64 } //1 Ph}u$|8rvCsw873~dkBf?IM?vuZTljVtYBNmAXZ6%l|DWHHqVotDfxQSJnd
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}