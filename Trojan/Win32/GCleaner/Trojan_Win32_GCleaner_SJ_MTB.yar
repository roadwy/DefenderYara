
rule Trojan_Win32_GCleaner_SJ_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.SJ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6d 4f 62 6a 43 72 65 61 74 65 28 22 57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 2e 31 22 29 0a 77 68 72 2e 4f 70 65 6e 28 22 47 45 54 22 2c 20 22 68 74 74 70 3a 2f 2f 31 37 38 2e 31 36 2e 35 32 2e 36 35 2f 73 75 63 63 65 73 73 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}