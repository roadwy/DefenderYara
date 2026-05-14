
rule Trojan_Win64_ArcaneStealer_ATC_MTB{
	meta:
		description = "Trojan:Win64/ArcaneStealer.ATC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {41 72 63 61 6e 65 20 47 72 61 62 62 65 72 20 6d 6f 64 75 6c 65 20 6c 6f 61 64 65 64 } //1 Arcane Grabber module loaded
		$a_01_1 = {41 6c 72 65 61 64 79 20 72 75 6e 6e 69 6e 67 20 61 73 20 61 64 6d 69 6e 2c 20 73 74 61 72 74 69 6e 67 20 64 69 72 65 63 74 6c 79 } //1 Already running as admin, starting directly
		$a_01_2 = {4e 6f 74 20 61 64 6d 69 6e 2c 20 61 74 74 65 6d 70 74 69 6e 67 20 65 6c 65 76 61 74 69 6f 6e 20 76 69 61 20 72 75 6e 64 6c 6c 33 32 } //1 Not admin, attempting elevation via rundll32
		$a_01_3 = {45 6c 65 76 61 74 65 64 20 69 6e 73 74 61 6e 63 65 20 63 6f 6d 70 6c 65 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Elevated instance completed successfully
		$a_01_4 = {53 74 61 72 74 69 6e 67 20 63 6f 6c 6c 65 63 74 69 6f 6e } //1 Starting collection
		$a_01_5 = {4b 69 6c 6c 69 6e 67 20 74 61 72 67 65 74 20 70 72 6f 63 65 73 73 65 73 } //1 Killing target processes
		$a_01_6 = {46 65 74 63 68 69 6e 67 20 49 50 20 69 6e 66 6f } //1 Fetching IP info
		$a_01_7 = {55 70 6c 6f 61 64 20 53 55 43 43 45 53 53 } //1 Upload SUCCESS
		$a_01_8 = {55 70 6c 6f 61 64 20 46 41 49 4c 45 44 20 61 66 74 65 72 20 35 20 61 74 74 65 6d 70 74 73 } //1 Upload FAILED after 5 attempts
		$a_01_9 = {67 72 61 62 62 65 72 5f 62 6f 75 6e 64 61 72 79 } //1 grabber_boundary
		$a_01_10 = {64 00 4c 00 6f 00 61 00 64 00 65 00 72 00 47 00 72 00 61 00 62 00 62 00 65 00 72 00 2f 00 31 00 2e 00 30 00 } //1 dLoaderGrabber/1.0
		$a_01_11 = {41 00 72 00 63 00 61 00 6e 00 65 00 2f 00 31 00 2e 00 30 00 } //1 Arcane/1.0
		$a_01_12 = {61 00 72 00 63 00 61 00 6e 00 65 00 5f 00 6c 00 65 00 } //1 arcane_le
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}