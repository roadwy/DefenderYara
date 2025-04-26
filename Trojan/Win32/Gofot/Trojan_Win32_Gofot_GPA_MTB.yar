
rule Trojan_Win32_Gofot_GPA_MTB{
	meta:
		description = "Trojan:Win32/Gofot.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_81_0 = {70 72 61 63 74 69 63 61 6c 6d 61 6c 77 61 72 65 61 6e 61 6c 79 73 69 73 2e 63 6f 6d 2f 75 70 64 61 74 65 72 2e 65 78 65 } //5 practicalmalwareanalysis.com/updater.exe
		$a_01_1 = {5c 77 69 6e 75 70 2e 65 78 65 00 00 25 73 25 73 } //1
		$a_01_2 = {5c 73 79 73 74 65 6d 33 32 5c 77 75 70 64 6d 67 72 64 2e 65 78 65 00 00 25 73 25 73 } //1
	condition:
		((#a_81_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}