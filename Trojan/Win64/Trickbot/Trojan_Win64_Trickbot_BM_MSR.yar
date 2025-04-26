
rule Trojan_Win64_Trickbot_BM_MSR{
	meta:
		description = "Trojan:Win64/Trickbot.BM!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 51 44 51 37 75 74 28 6b 6c 56 4b 69 6e 40 43 49 53 52 65 5f 56 75 33 59 58 5e 62 4b 55 44 44 54 44 68 4a 55 6a 4d 4d 5a 41 26 3c 6d 53 72 3e 66 45 6a 26 3e 4e 47 47 4e 75 66 } //1 1QDQ7ut(klVKin@CISRe_Vu3YX^bKUDDTDhJUjMMZA&<mSr>fEj&>NGGNuf
		$a_01_1 = {5c 57 69 6e 64 6f 77 73 53 44 4b 37 2d 53 61 6d 70 6c 65 73 2d 6d 61 73 74 65 72 5c 57 69 6e 64 6f 77 73 53 44 4b 37 2d 53 61 6d 70 6c 65 73 2d 6d 61 73 74 65 72 5c 63 6f 6d 5c 61 64 6d 69 6e 69 73 74 72 61 74 69 6f 6e 5c 73 70 79 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 43 6f 6d 53 70 79 2e 70 64 62 } //1 \WindowsSDK7-Samples-master\WindowsSDK7-Samples-master\com\administration\spy\x64\Release\ComSpy.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}