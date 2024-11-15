
rule Trojan_Win32_CryptBot_GPA_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_81_0 = {2f 2f 75 70 64 61 74 65 2d 6c 65 64 67 65 72 2e 6e 65 74 2f 75 70 64 61 74 65 } //4 //update-ledger.net/update
		$a_81_1 = {55 73 65 42 61 73 69 63 50 61 72 73 69 6e 67 20 2d 55 73 65 72 41 67 65 6e 74 } //1 UseBasicParsing -UserAgent
	condition:
		((#a_81_0  & 1)*4+(#a_81_1  & 1)*1) >=5
 
}