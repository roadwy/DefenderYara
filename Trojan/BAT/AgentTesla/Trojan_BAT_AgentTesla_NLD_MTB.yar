
rule Trojan_BAT_AgentTesla_NLD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 74 72 61 6e 73 66 65 72 2e 69 6f 2f 64 61 74 61 2d 70 61 63 6b 61 67 65 2f 46 75 64 58 37 68 73 47 2f 64 6f 77 6e 6c 6f 61 64 } //1 filetransfer.io/data-package/FudX7hsG/download
		$a_01_1 = {61 36 38 30 2d 34 63 63 31 2d 38 66 66 34 } //1 a680-4cc1-8ff4
		$a_81_2 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //1 GetByteArrayAsync
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_4 = {53 62 69 78 73 6d 78 66 7a 6a 65 76 67 76 67 65 74 2e 4f 78 68 64 73 68 77 6b 65 66 73 74 6d 63 79 } //1 Sbixsmxfzjevgvget.Oxhdshwkefstmcy
		$a_81_5 = {45 6c 67 72 75 7a 64 63 76 6f 75 7a 6b 61 6e 75 6a 6c } //1 Elgruzdcvouzkanujl
		$a_01_6 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}