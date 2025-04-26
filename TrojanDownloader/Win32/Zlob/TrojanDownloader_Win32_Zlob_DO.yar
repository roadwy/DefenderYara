
rule TrojanDownloader_Win32_Zlob_DO{
	meta:
		description = "TrojanDownloader:Win32/Zlob.DO,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 08 00 00 "
		
	strings :
		$a_01_0 = {32 36 36 2c 31 32 39 20 62 79 74 65 73 } //5 266,129 bytes
		$a_01_1 = {43 6c 69 63 6b 20 4f 4b 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 61 6e 74 69 76 69 72 75 73 20 73 6f 66 74 77 61 72 65 20 61 6e 64 20 70 61 73 73 20 66 75 6c 6c 20 73 79 73 74 65 6d 20 73 63 61 6e 20 74 6f } //5 Click OK to download antivirus software and pass full system scan to
		$a_01_2 = {57 6f 75 6c 64 20 79 6f 75 20 6c 69 6b 65 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 6c 61 74 65 73 74 20 76 65 72 73 69 6f 6e 20 6f 66 20 61 6e 74 69 76 69 72 75 73 20 73 6f 66 74 77 61 72 65 3f } //5 Would you like to download latest version of antivirus software?
		$a_01_3 = {43 6c 69 63 6b 20 4f 4b 20 74 6f 20 64 6f 6e 77 6c 6f 61 64 20 61 6e 74 69 73 70 79 77 61 72 65 20 73 6f 66 74 77 61 72 65 2e } //5 Click OK to donwload antispyware software.
		$a_01_4 = {65 6d 61 69 6c 20 61 64 64 72 65 73 73 65 73 20 66 72 6f 6d 20 74 68 65 20 63 6f 6d 70 72 6f 6d 69 73 65 64 20 63 6f 6d 70 75 74 65 72 2e } //5 email addresses from the compromised computer.
		$a_01_5 = {54 68 69 73 20 66 61 74 61 6c 20 65 72 72 6f 72 20 70 72 6f 62 61 62 6c 79 20 6f 63 63 75 72 65 64 20 62 65 63 61 75 73 65 20 6f 66 20 61 20 76 69 72 75 73 20 6f 6e 20 79 6f 75 72 20 50 43 2e } //5 This fatal error probably occured because of a virus on your PC.
		$a_01_6 = {4c 6f 77 20 49 6e 74 65 72 6e 65 74 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 73 70 65 65 64 } //5 Low Internet connection speed
		$a_01_7 = {4c 6f 77 20 73 79 73 74 65 6d 20 70 65 72 66 6f 6d 61 6e 63 65 } //5 Low system perfomance
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5) >=35
 
}