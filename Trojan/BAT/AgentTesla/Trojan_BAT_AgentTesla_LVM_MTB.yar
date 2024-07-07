
rule Trojan_BAT_AgentTesla_LVM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 16 73 90 01 03 0a 73 90 01 03 0a 0c 08 07 6f 90 01 03 0a 07 6f 90 01 03 0a 80 90 01 03 04 de 1e 90 00 } //1
		$a_03_1 = {16 0d 2b 30 08 09 9a 13 04 11 04 6f 90 01 03 0a 72 90 01 03 70 28 90 01 03 0a 2c 14 11 04 14 14 6f 90 01 03 0a 26 72 90 01 03 70 28 90 01 03 0a 09 17 58 0d 09 08 8e 69 32 ca 07 17 58 0b 07 06 8e 69 32 b3 90 00 } //1
		$a_01_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 WindowsFormsApp1.Properties.Resources
		$a_01_3 = {44 65 63 6f 64 65 72 } //1 Decoder
		$a_01_4 = {50 72 6f 67 72 61 6d } //1 Program
		$a_01_5 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_01_6 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}