
rule Trojan_Win64_RedParrot_HC{
	meta:
		description = "Trojan:Win64/RedParrot.HC,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 64 65 20 68 65 61 70 20 61 6e 61 6c 79 73 69 73 } //1 code heap analysis
		$a_01_1 = {5b 4d 61 63 68 43 6f 64 65 5d } //1 [MachCode]
		$a_01_2 = {4b 65 79 53 69 7a 65 } //1 KeySize
		$a_01_3 = {4d 6f 64 75 6c 75 73 53 69 7a 65 } //1 ModulusSize
		$a_03_4 = {32 00 30 00 32 00 35 00 30 00 35 00 30 00 37 00 2d 00 32 00 33 00 30 00 30 00 30 00 ?? ?? 2e 00 6c 00 6f 00 67 00 } //2
		$a_00_5 = {53 00 70 00 6c 00 75 00 6e 00 6b 00 39 00 34 00 31 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5f 00 } //2 Splunk941Install_
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2+(#a_00_5  & 1)*2) >=7
 
}