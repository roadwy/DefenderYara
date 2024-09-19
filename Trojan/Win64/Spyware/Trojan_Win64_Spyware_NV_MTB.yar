
rule Trojan_Win64_Spyware_NV_MTB{
	meta:
		description = "Trojan:Win64/Spyware.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {e8 a8 5b 00 00 48 8b 4c 24 30 e8 ee ba 01 00 8b d0 33 c9 e8 75 be 01 00 ba 01 00 00 00 b9 09 00 00 00 e8 66 be 01 00 48 8b 4c 24 30 } //2
		$a_01_1 = {42 72 61 76 65 53 6f 66 74 77 61 72 65 42 72 61 76 65 2d 42 72 6f 77 73 65 72 74 72 79 69 6e 67 20 74 6f 20 6f 70 65 6e 20 62 72 61 76 65 20 73 74 61 74 65 20 66 69 6c 65 } //1 BraveSoftwareBrave-Browsertrying to open brave state file
		$a_01_2 = {53 65 6e 64 69 6e 67 20 42 72 61 76 65 20 63 6f 6f 6b 69 65 73 } //1 Sending Brave cookies
		$a_01_3 = {5b 53 74 65 65 6c 65 72 69 6e 6f 20 31 2e 30 5d 20 65 78 65 63 75 74 65 64 20 6f 6e 20 74 61 72 67 65 74 3a } //1 [Steelerino 1.0] executed on target:
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}