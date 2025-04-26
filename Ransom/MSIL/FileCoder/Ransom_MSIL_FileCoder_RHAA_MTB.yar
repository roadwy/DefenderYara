
rule Ransom_MSIL_FileCoder_RHAA_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.RHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 43 72 79 2e 65 78 65 } //2 NoCry.exe
		$a_01_1 = {79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 2e } //1 your important files are encrypted.
		$a_01_2 = {4f 6f 6f 6f 6f 70 73 20 41 6c 6c 20 59 6f 75 72 20 46 69 6c 65 73 20 41 72 65 20 45 6e 63 72 79 70 74 65 64 20 2c 4e 6f 43 72 79 } //1 Ooooops All Your Files Are Encrypted ,NoCry
		$a_01_3 = {43 6f 6e 74 61 63 74 20 4d 65 20 41 74 20 45 6d 61 69 6c 20 54 6f 20 47 65 74 20 41 20 4b 65 79 } //1 Contact Me At Email To Get A Key
		$a_03_4 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 08 00 00 5a 05 00 00 06 00 00 00 00 00 00 2e 78 05 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2) >=7
 
}