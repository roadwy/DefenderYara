
rule Trojan_Win32_Small_ZDA{
	meta:
		description = "Trojan:Win32/Small.ZDA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 6f 00 00 ff ff ff ff 04 00 00 00 6b 69 6c 6c 00 00 00 00 ff ff ff ff 04 00 00 00 6d 73 67 73 00 00 00 00 ff ff ff ff 03 00 00 00 73 79 73 00 ff ff ff ff 01 00 00 00 30 00 00 00 ff ff ff ff 04 00 00 00 78 78 6a 67 00 00 00 00 ff ff ff ff 03 00 00 00 72 75 6e 00 ff ff ff ff 03 00 00 00 6d 73 67 00 ff ff ff ff 03 00 00 00 76 65 72 00 ff ff ff ff 06 00 00 00 6d 79 64 6f 77 6e 00 00 ff ff ff ff 03 00 00 00 31 38 30 00 ff ff ff ff 04 00 00 00 70 7a 6a 67 00 00 00 00 ff ff ff ff 01 00 00 00 32 00 00 00 ff ff ff ff 05 00 00 00 } //1
		$a_01_1 = {64 65 6c 61 79 00 00 00 ff ff ff ff 07 00 00 00 7a 68 71 62 5f 64 66 00 ff ff ff ff 3f 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 5c 72 75 6e 00 ff ff ff ff 07 00 00 00 53 74 61 72 74 75 70 00 ff ff ff ff 40 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00 00 00 00 ff ff ff ff 0b 00 00 00 5c 64 66 7a 68 71 62 2e 65 78 65 00 ff ff ff ff 02 00 00 00 66 6e 00 00 ff ff ff ff 06 00 00 00 64 65 6c 65 74 65 00 00 ff ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}