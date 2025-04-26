
rule Trojan_BAT_FakeFilecoder_NFA_MTB{
	meta:
		description = "Trojan:BAT/FakeFilecoder.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {54 50 46 32 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 TPF2.Properties.Resources.resources
		$a_01_1 = {54 61 70 50 69 46 2e 50 72 6f 70 65 72 74 69 65 73 } //1 TapPiF.Properties
		$a_01_2 = {59 4f 55 20 42 45 43 4f 4d 45 20 54 48 45 20 56 49 43 54 49 4d 20 4f 46 20 54 41 46 2e 47 20 4d 41 4c 57 41 52 45 21 } //1 YOU BECOME THE VICTIM OF TAF.G MALWARE!
		$a_01_3 = {42 6f 72 69 6e 67 20 6f 66 20 50 72 6f 6a 65 63 74 20 66 6f 72 20 42 6f 6d 62 20 6f 66 20 45 78 74 72 61 63 74 69 6e 67 20 46 69 6c 65 73 } //1 Boring of Project for Bomb of Extracting Files
		$a_01_4 = {79 6f 75 72 20 73 6f 6d 65 20 66 69 6c 65 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //1 your some file has been encrypted!
		$a_01_5 = {48 6f 77 20 74 6f 20 44 65 63 72 79 70 74 20 4d 79 20 46 69 6c 65 73 3f } //1 How to Decrypt My Files?
		$a_01_6 = {40 50 6c 65 61 73 65 5f 52 65 61 64 5f 4d 65 40 2e 65 78 65 } //1 @Please_Read_Me@.exe
		$a_01_7 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}