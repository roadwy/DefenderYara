
rule Trojan_Win32_AppinElephant_LKV_MTB{
	meta:
		description = "Trojan:Win32/AppinElephant.LKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 65 6d 70 5c 65 6c 61 6e 63 65 5c 41 75 74 6f 54 72 61 6e 73 66 65 72 32 5c 52 65 6c 65 61 73 65 5c 41 75 74 6f 54 72 61 6e 73 66 65 72 32 2e 70 64 62 } //1 temp\elance\AutoTransfer2\Release\AutoTransfer2.pdb
		$a_01_1 = {46 00 74 00 70 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 FtpPassword
		$a_01_2 = {53 65 6e 64 69 6e 67 20 69 70 63 6f 6e 66 69 67 2e 65 78 65 20 6f 75 74 70 75 74 } //1 Sending ipconfig.exe output
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}