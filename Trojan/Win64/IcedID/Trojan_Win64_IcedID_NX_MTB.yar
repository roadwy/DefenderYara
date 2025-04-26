
rule Trojan_Win64_IcedID_NX_MTB{
	meta:
		description = "Trojan:Win64/IcedID.NX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {56 66 75 67 64 73 68 66 6a 68 67 79 55 41 53 68 6a 61 73 68 67 79 75 73 6a 61 66 } //1 VfugdshfjhgyUAShjashgyusjaf
		$a_01_1 = {41 42 72 52 6a 37 44 64 53 54 79 70 63 44 68 56 36 52 53 } //1 ABrRj7DdSTypcDhV6RS
		$a_01_2 = {42 74 4f 6d 4e 54 59 61 77 6b 62 71 56 61 4c 67 4c 4f 78 6d 72 38 5a 6f 45 } //1 BtOmNTYawkbqVaLgLOxmr8ZoE
		$a_01_3 = {42 74 56 69 69 59 76 49 48 47 6d 64 77 62 65 71 67 79 4e } //1 BtViiYvIHGmdwbeqgyN
		$a_01_4 = {46 79 7a 55 77 38 74 6f 73 69 37 4a 6d 7a 53 64 39 4b 79 70 44 6e 46 35 62 62 } //1 FyzUw8tosi7JmzSd9KypDnF5bb
		$a_01_5 = {46 55 55 54 54 33 41 6f 72 44 4a 68 4d 4e 7a 64 4e 6a 6c 65 38 47 } //1 FUUTT3AorDJhMNzdNjle8G
		$a_01_6 = {78 55 7a 7a 48 72 63 65 67 47 5a 4f 63 5a 57 42 55 59 34 78 39 30 63 31 65 4a 41 56 62 79 } //1 xUzzHrcegGZOcZWBUY4x90c1eJAVby
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}