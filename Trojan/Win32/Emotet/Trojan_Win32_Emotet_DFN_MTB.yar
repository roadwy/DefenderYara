
rule Trojan_Win32_Emotet_DFN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {03 c1 b9 7f 1a 00 00 99 f7 f9 8a 03 83 c4 08 8a 54 14 14 32 c2 88 03 } //1
		$a_00_1 = {03 c1 b9 3a 17 00 00 99 f7 f9 8a 03 83 c4 08 8a 54 14 14 32 c2 88 03 } //1
		$a_81_2 = {5a 4e 68 4c 71 75 77 34 64 4d 71 57 74 74 45 6c 51 74 35 45 50 4e 38 30 4b 57 39 4c 74 48 46 7a 58 76 49 62 43 79 } //1 ZNhLquw4dMqWttElQt5EPN80KW9LtHFzXvIbCy
		$a_81_3 = {37 36 53 62 44 50 62 46 39 78 4d 53 4a 30 6a 53 73 69 4a 35 59 6d 31 4b 45 47 54 74 78 37 34 42 74 } //1 76SbDPbF9xMSJ0jSsiJ5Ym1KEGTtx74Bt
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}