
rule Trojan_Win64_RALord_SACR_MTB{
	meta:
		description = "Trojan:Win64/RALord.SACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {52 41 4c 6f 72 64 20 72 61 6e 73 6f 6d 77 61 72 65 20 } //2 RALord ransomware 
		$a_81_1 = {54 68 72 65 61 64 50 6f 6f 6c 42 75 69 6c 64 45 72 72 6f 72 6b 69 6e 64 52 45 41 44 4d 45 2d 2e 74 78 74 } //1 ThreadPoolBuildErrorkindREADME-.txt
		$a_81_2 = {79 6f 75 20 63 61 6e 20 72 65 63 6f 76 65 72 20 74 68 65 20 66 69 6c 65 73 20 62 79 20 63 6f 6e 74 61 63 74 20 75 73 20 61 6e 64 20 70 61 79 20 74 68 65 20 72 61 6e 73 6f 6d 20 } //1 you can recover the files by contact us and pay the ransom 
		$a_81_3 = {79 6f 75 20 73 65 65 20 74 68 69 73 20 52 65 61 64 6d 65 20 69 74 73 20 6d 65 61 6e 20 79 6f 75 20 75 6e 64 65 72 20 63 6f 6e 74 72 6f 6c 6c 20 62 79 20 52 4c 6f 72 64 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 you see this Readme its mean you under controll by RLord ransomware
		$a_81_4 = {74 68 65 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 76 65 72 79 74 68 69 6e 67 20 64 6f 6e 65 20 } //1 the data has been stolen and everything done 
		$a_81_5 = {70 6c 65 61 73 65 20 64 6f 20 6e 6f 74 20 74 6f 75 63 68 20 74 68 65 20 66 69 6c 65 73 20 62 65 63 6f 75 73 65 20 77 65 20 63 61 6e 27 74 20 64 65 63 72 79 70 74 20 69 74 20 69 66 20 79 6f 75 20 74 6f 75 63 68 20 69 74 } //1 please do not touch the files becouse we can't decrypt it if you touch it
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}