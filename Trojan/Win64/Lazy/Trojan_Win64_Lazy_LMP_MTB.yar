
rule Trojan_Win64_Lazy_LMP_MTB{
	meta:
		description = "Trojan:Win64/Lazy.LMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_81_0 = {25 30 34 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 33 64 25 30 31 64 25 30 32 64 25 30 31 64 } //1 %04d%02d%02d%02d%02d%02d%03d%01d%02d%01d
		$a_81_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 } //2 C:\Users\Public
		$a_81_2 = {68 74 74 70 3a 2f 2f 67 6f 6f 67 6c 65 71 2e 73 33 2e 61 70 2d 73 6f 75 74 68 65 61 73 74 2d 31 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f 37 32 31 37 2e 7a 69 70 } //3 http://googleq.s3.ap-southeast-1.amazonaws.com/7217.zip
		$a_81_3 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 6e 44 74 72 54 35 36 31 34 35 36 35 2e 64 61 74 } //4 C:\Users\Public\nDtrT5614565.dat
		$a_81_4 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 69 41 70 70 6c 65 5c 69 41 70 70 6c 65 53 65 74 75 70 2e 65 78 65 } //5 C:\Users\Public\iApple\iAppleSetup.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5) >=15
 
}