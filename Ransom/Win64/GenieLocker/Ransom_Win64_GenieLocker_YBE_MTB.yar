
rule Ransom_Win64_GenieLocker_YBE_MTB{
	meta:
		description = "Ransom:Win64/GenieLocker.YBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 65 6e 69 65 4c 6f 63 6b 65 72 } //1 GenieLocker
		$a_01_1 = {67 65 6e 69 65 5f 65 6e 63 72 79 70 74 20 5b 6f 70 74 69 6f 6e 73 5d 20 5b 70 61 74 68 5d } //1 genie_encrypt [options] [path]
		$a_01_2 = {45 6e 63 72 79 70 74 69 6f 6e 20 70 65 72 63 65 6e 74 61 67 65 } //1 Encryption percentage
		$a_01_3 = {77 69 6c 6c 20 65 6e 63 72 79 70 74 20 61 6c 6c 20 64 72 69 76 65 73 } //1 will encrypt all drives
		$a_01_4 = {4f 4c 4c 59 44 42 47 } //1 OLLYDBG
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}