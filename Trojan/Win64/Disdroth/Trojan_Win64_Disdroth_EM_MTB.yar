
rule Trojan_Win64_Disdroth_EM_MTB{
	meta:
		description = "Trojan:Win64/Disdroth.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba 40 00 00 00 41 8b c8 83 e1 3f 2b d1 8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe 00 07 05 00 eb 89 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Disdroth_EM_MTB_2{
	meta:
		description = "Trojan:Win64/Disdroth.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 54 6f 6e 79 20 53 74 61 72 6b 5c 2e 72 75 73 74 75 70 5c 74 6f 6f 6c 63 68 61 69 6e 73 } //1 C:\Users\Tony Stark\.rustup\toolchains
		$a_81_1 = {50 72 69 6f 72 69 74 79 73 74 72 65 61 6d 5f 69 64 64 65 70 65 6e 64 65 6e 63 79 } //1 Prioritystream_iddependency
		$a_81_2 = {50 69 6e 67 61 63 6b 70 61 79 6c 6f 61 64 } //1 Pingackpayload
		$a_81_3 = {5f 64 65 73 6b 74 6f 70 2e 70 64 62 } //1 _desktop.pdb
		$a_81_4 = {5c 63 6d 64 2e 65 78 65 } //1 \cmd.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}