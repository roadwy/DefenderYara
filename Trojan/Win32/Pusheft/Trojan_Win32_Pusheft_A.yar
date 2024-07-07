
rule Trojan_Win32_Pusheft_A{
	meta:
		description = "Trojan:Win32/Pusheft.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {2f 67 72 65 65 6e 2f 90 01 01 2e 64 61 74 90 00 } //1
		$a_01_1 = {62 6c 61 6e 63 61 78 2e 64 61 74 } //1 blancax.dat
		$a_01_2 = {70 75 73 73 79 74 68 65 66 74 2e 63 6f 6d } //1 pussytheft.com
		$a_01_3 = {28 3c 69 70 5b 5e 3e 5d 2a 3e 5b 5e 3c 5d 2a 3c 2f 69 70 3e 5b 5e 3c 5d 2a 3c 70 61 63 6b 65 74 } //1 (<ip[^>]*>[^<]*</ip>[^<]*<packet
		$a_01_4 = {89 48 08 8b 55 08 8b 42 04 03 45 a0 89 45 88 8b 4d 88 8a 55 8c 88 11 e9 4b fd ff ff } //2
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=4
 
}