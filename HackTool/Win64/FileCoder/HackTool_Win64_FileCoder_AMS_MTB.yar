
rule HackTool_Win64_FileCoder_AMS_MTB{
	meta:
		description = "HackTool:Win64/FileCoder.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {54 68 65 20 70 72 6f 67 72 61 6d 20 79 6f 75 20 61 72 65 20 74 72 79 69 6e 67 20 74 6f 20 72 75 6e 20 69 73 20 6d 61 6c 77 61 72 65 2c 20 74 68 61 74 20 63 61 6e 20 64 6f 20 72 65 61 6c 20 68 61 72 6d 20 74 6f 20 79 6f 75 72 20 6d 61 63 68 69 6e 65 } //The program you are trying to run is malware, that can do real harm to your machine  5
		$a_80_1 = {54 79 70 65 20 22 59 65 73 2c 20 49 20 63 6f 6e 73 65 6e 74 2e 22 20 74 6f 20 63 6f 6e 73 65 6e 74 2e } //Type "Yes, I consent." to consent.  2
		$a_80_2 = {53 61 76 69 6e 67 20 63 6f 6e 73 65 6e 74 20 77 69 74 68 20 74 69 6d 65 20 61 6e 64 20 64 61 74 65 } //Saving consent with time and date  1
		$a_80_3 = {41 73 20 65 78 70 6c 61 69 6e 65 64 2c 20 70 72 69 6f 72 20 74 6f 20 74 68 65 20 63 6f 6e 73 65 6e 74 2c 20 61 6c 6c 20 70 72 6f 67 72 61 6d 20 61 75 74 68 6f 72 73 20 61 72 65 20 6e 6f 74 20 6c 69 61 62 6c 65 20 66 6f 72 20 61 6e 79 20 64 61 6d 61 67 65 73 } //As explained, prior to the consent, all program authors are not liable for any damages  1
		$a_80_4 = {74 68 69 73 20 70 72 6f 67 72 61 6d 20 6d 61 79 20 70 65 72 6d 61 6e 65 6e 74 6c 79 20 64 61 6d 61 67 65 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //this program may permanently damage your computer  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=10
 
}