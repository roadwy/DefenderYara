
rule Trojan_Win64_IcedID_AY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 89 05 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 8b 89 ?? ?? ?? ?? 8b 40 ?? 33 c1 35 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 8b 49 ?? 2b c8 8b c1 48 ?? ?? ?? ?? ?? ?? 89 41 ?? e9 ?? ?? ?? ?? b8 ?? ?? ?? ?? 48 ?? ?? ?? 48 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_IcedID_AY_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 "
		
	strings :
		$a_01_0 = {42 47 72 48 68 69 49 57 6a } //1 BGrHhiIWj
		$a_01_1 = {42 69 44 31 64 61 47 53 67 56 69 } //1 BiD1daGSgVi
		$a_01_2 = {47 45 47 66 42 4e 47 59 57 59 6d } //1 GEGfBNGYWYm
		$a_01_3 = {48 43 6a 33 6f 52 45 6e } //1 HCj3oREn
		$a_01_4 = {4a 30 51 45 49 56 30 56 4e 43 } //1 J0QEIV0VNC
		$a_01_5 = {42 49 64 54 74 58 61 55 79 4e 4b } //1 BIdTtXaUyNK
		$a_01_6 = {44 72 48 62 39 34 73 65 62 79 76 } //1 DrHb94sebyv
		$a_01_7 = {49 38 76 4d 55 52 72 50 4d 4c 69 } //1 I8vMURrPMLi
		$a_01_8 = {4b 37 71 6f 67 4e 4a 34 7a 42 59 } //1 K7qogNJ4zBY
		$a_01_9 = {4b 52 45 56 4d 59 67 62 66 54 43 } //1 KREVMYgbfTC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=5
 
}