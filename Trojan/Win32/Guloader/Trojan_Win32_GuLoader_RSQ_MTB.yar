
rule Trojan_Win32_GuLoader_RSQ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 63 6f 6e 63 6c 75 73 69 76 65 6e 65 73 73 5c 61 66 6c 69 72 65 6e 64 65 5c 6b 61 76 61 69 63 } //1 \conclusiveness\aflirende\kavaic
		$a_81_1 = {5c 64 69 64 61 63 74 69 76 65 5c 65 6e 65 70 72 6f 6b 75 72 61 2e 69 6e 69 } //1 \didactive\eneprokura.ini
		$a_81_2 = {6b 6f 6d 70 61 6b 74 68 65 64 65 6e 5c 49 6e 64 66 6f 65 72 65 6c 73 65 6e 31 32 36 } //1 kompaktheden\Indfoerelsen126
		$a_81_3 = {75 6e 63 6f 6e 6e 65 63 74 65 64 6e 65 73 73 20 66 61 6d 65 6c 69 63 } //1 unconnectedness famelic
		$a_81_4 = {73 70 72 69 6e 6b 20 66 6f 72 73 76 61 72 73 76 72 6b 65 72 73 20 6b 6c 6f 76 62 65 73 6b 72 69 6e 67 } //1 sprink forsvarsvrkers klovbeskring
		$a_81_5 = {73 6b 69 6d 73 20 74 72 6f 67 6f 6e 20 73 6b 72 69 64 74 6b 69 6c 65 6e } //1 skims trogon skridtkilen
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}