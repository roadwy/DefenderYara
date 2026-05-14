
rule Trojan_Win64_Tedy_LMA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 8b 0f 48 ff c6 49 8b 47 08 48 2b c1 48 c1 f8 03 48 0f af c2 48 3b f0 } //10
		$a_81_1 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 63 6f 72 72 75 70 74 65 64 2e 20 43 6c 69 63 6b 20 4f 4b 20 74 6f 20 63 6f 6e 74 69 6e 75 65 2e 2e 2e } //1 Your computer is corrupted. Click OK to continue...
		$a_81_2 = {48 41 50 50 59 20 4e 45 57 20 59 45 41 52 20 32 30 32 36 2e 2e 2e 20 6f 72 20 69 73 20 69 74 } //2 HAPPY NEW YEAR 2026... or is it
		$a_81_3 = {56 69 72 75 73 20 64 65 74 65 63 74 65 64 2e 20 46 6f 72 6d 61 74 74 69 6e 67 20 43 3a 5c 20 69 6e 20 70 72 6f 67 72 65 73 73 2e 2e 2e } //3 Virus detected. Formatting C:\ in progress...
		$a_81_4 = {59 6f 75 72 20 73 6f 75 6c 20 62 65 6c 6f 6e 67 73 20 74 6f 20 75 73 20 6e 6f 77 2e 20 4f 4b } //4 Your soul belongs to us now. OK
		$a_81_5 = {59 6f 75 72 20 50 43 20 69 73 20 64 79 69 6e 67 2e 20 4f 4b 20 3d 20 61 63 63 65 70 74 20 66 61 74 65 } //5 Your PC is dying. OK = accept fate
	condition:
		((#a_01_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*2+(#a_81_3  & 1)*3+(#a_81_4  & 1)*4+(#a_81_5  & 1)*5) >=25
 
}