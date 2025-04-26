
rule Trojan_Win32_Vasnasea{
	meta:
		description = "Trojan:Win32/Vasnasea,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 75 73 63 6f 63 00 90 04 01 1a 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a 90 04 04 1a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 00 54 62 72 69 7a 00 59 69 6c 6c 71 78 66 76 76 90 09 0f 00 90 04 0a 1a 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 2e 64 6c 6c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}