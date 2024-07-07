
rule Trojan_BAT_AgentTesla_LDD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0e 00 00 "
		
	strings :
		$a_01_0 = {23 66 73 64 67 68 63 67 67 66 73 64 66 73 64 2e 64 6c 6c 23 } //1 #fsdghcggfsdfsd.dll#
		$a_01_1 = {23 66 73 64 68 63 66 73 64 66 2e 64 6c 6c 23 } //1 #fsdhcfsdf.dll#
		$a_01_2 = {23 66 73 64 68 68 61 68 66 66 64 73 66 2e 64 6c 6c 23 } //1 #fsdhhahffdsf.dll#
		$a_01_3 = {23 66 73 64 67 68 68 68 68 68 68 73 64 67 66 64 73 66 2e 64 6c 6c 23 } //1 #fsdghhhhhhsdgfdsf.dll#
		$a_01_4 = {67 66 64 66 66 66 66 66 66 68 66 66 66 67 } //1 gfdffffffhfffg
		$a_01_5 = {00 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 68 00 } //1
		$a_01_6 = {68 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 6b 63 } //1 hkkkkkkkkkkkkkkkkkkkkkkkkc
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_8 = {23 66 73 64 67 66 67 66 66 73 64 66 23 } //1 #fsdgfgffsdf#
		$a_01_9 = {23 66 73 64 68 68 61 66 66 64 73 66 2e 64 6c 6c 23 } //1 #fsdhhaffdsf.dll#
		$a_01_10 = {23 66 73 68 67 67 64 66 73 73 68 67 66 68 64 66 73 64 66 2e 64 6c 6c 23 } //1 #fshggdfsshgfhdfsdf.dll#
		$a_01_11 = {23 66 73 64 66 73 64 67 67 66 64 73 66 2e 64 6c 6c 23 } //1 #fsdfsdggfdsf.dll#
		$a_01_12 = {65 77 61 66 66 66 73 66 61 73 63 63 66 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 67 61 73 66 77 } //1 ewafffsfasccfggggggggggggggggggggggggggasfw
		$a_01_13 = {66 73 61 66 61 66 77 77 77 77 77 77 77 77 61 66 } //1 fsafafwwwwwwwwaf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=7
 
}