
rule Trojan_BAT_Jalapeno_SPZB_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SPZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {12 02 12 03 28 ?? 00 00 06 13 04 11 04 2c 13 12 03 7b 01 00 00 04 7e 0c 00 00 0a 28 ?? 00 00 0a 2c 18 16 13 05 2b 0d 1f 0a 28 ?? 00 00 0a 11 05 17 58 13 05 11 05 19 32 ee 2a 12 03 7b 01 00 00 04 7e 0c 00 00 0a 03 8e 69 20 00 30 00 00 1f 40 28 ?? 00 00 06 13 06 11 06 7e 0c 00 00 0a 28 ?? 00 00 0a 2c 07 09 28 ?? 00 00 06 2a 12 03 7b 01 00 00 04 11 06 03 03 8e 69 12 07 28 ?? 00 00 06 2c 0e 11 07 7e 0c 00 00 0a 28 ?? 00 00 0a 2c 07 } //2
		$a_00_1 = {41 7a 65 72 6f 50 75 6d } //1 AzeroPum
		$a_00_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //1 VirtualAllocEx
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}