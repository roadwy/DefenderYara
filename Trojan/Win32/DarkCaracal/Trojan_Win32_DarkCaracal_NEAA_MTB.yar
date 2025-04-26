
rule Trojan_Win32_DarkCaracal_NEAA_MTB{
	meta:
		description = "Trojan:Win32/DarkCaracal.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 "
		
	strings :
		$a_01_0 = {6d 73 69 6e 66 6f 33 32 2e 65 78 65 } //5 msinfo32.exe
		$a_01_1 = {46 64 66 61 64 61 64 61 73 64 73 61 37 64 38 73 61 64 38 61 } //2 Fdfadadasdsa7d8sad8a
		$a_01_2 = {4a 48 44 53 4a 44 48 37 65 37 77 37 65 77 37 65 36 65 77 37 } //2 JHDSJDH7e7w7ew7e6ew7
		$a_01_3 = {56 44 6b 64 6a 61 6b 64 6a 61 6b 64 73 61 64 61 64 61 73 64 61 } //2 VDkdjakdjakdsadadasda
		$a_01_4 = {43 45 44 52 45 4b 41 53 4d 50 53 } //2 CEDREKASMPS
		$a_01_5 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //2 Internet Explorer\iexplore.exe
		$a_01_6 = {70 6f 4f 77 6e 65 72 46 6f 72 6d 43 65 6e 74 65 72 } //1 poOwnerFormCenter
		$a_01_7 = {54 44 43 50 5f 62 6c 6f 63 6b 63 69 70 68 65 72 36 34 } //1 TDCP_blockcipher64
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=17
 
}