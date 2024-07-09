
rule Backdoor_Win32_Beastdoor_P{
	meta:
		description = "Backdoor:Win32/Beastdoor.P,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {5c 48 65 6c 70 5c [0-08] 2e 63 68 6d } //1
		$a_00_1 = {7c 74 72 61 66 66 69 63 7c 61 64 75 6c 74 7c 70 68 61 72 6d 61 7c 70 61 72 74 6e 65 72 7c 70 6f 72 6e 6f } //1 |traffic|adult|pharma|partner|porno
		$a_00_2 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 3b 20 55 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 65 6e 2d 55 53 3b 20 72 76 3a 31 2e 38 2e 31 2e 31 29 } //1 User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.1)
		$a_00_3 = {3a 32 30 38 32 0d 0a 3a 32 30 38 33 0d 0a 3a 32 30 38 36 0d 0a 3a 32 30 38 37 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}