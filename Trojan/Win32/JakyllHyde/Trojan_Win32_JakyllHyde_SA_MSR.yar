
rule Trojan_Win32_JakyllHyde_SA_MSR{
	meta:
		description = "Trojan:Win32/JakyllHyde.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {00 00 65 64 67 90 01 03 2e 64 61 74 } //1
		$a_01_1 = {65 33 65 37 65 37 31 61 30 62 32 38 62 35 65 39 36 63 63 34 39 32 65 36 33 36 37 32 32 66 37 33 } //3 e3e7e71a0b28b5e96cc492e636722f73
		$a_00_2 = {00 00 54 50 58 90 01 03 2e 64 61 74 } //1
		$a_01_3 = {41 64 62 46 6c 65 2e 74 6d 70 } //2 AdbFle.tmp
		$a_01_4 = {5b 00 42 00 41 00 43 00 4b 00 53 00 50 00 41 00 5b 00 50 00 41 00 47 00 45 00 20 00 44 00 4f 00 5b 00 43 00 41 00 50 00 53 00 20 00 4c 00 4f 00 5b 00 } //1 [BACKSPA[PAGE DO[CAPS LO[
		$a_01_5 = {2f 64 72 61 67 30 6e 2f 53 70 65 63 73 2f } //1 /drag0n/Specs/
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*3+(#a_00_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}