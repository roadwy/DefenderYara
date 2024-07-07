
rule Trojan_Win32_CredInfoStealer_B{
	meta:
		description = "Trojan:Win32/CredInfoStealer.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 77 65 62 43 72 65 64 73 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 77 65 62 43 72 65 64 73 2e 70 64 62 } //1 source\repos\webCreds\obj\Release\webCreds.pdb
		$a_01_1 = {3c 47 65 74 43 72 65 64 73 3e 67 5f 5f 47 65 74 56 61 75 6c 74 45 6c 65 6d 65 6e 74 56 61 6c 75 65 } //1 <GetCreds>g__GetVaultElementValue
		$a_00_2 = {5b 00 45 00 52 00 52 00 4f 00 52 00 5d 00 20 00 55 00 6e 00 61 00 62 00 6c 00 65 00 20 00 74 00 6f 00 20 00 65 00 6e 00 75 00 6d 00 65 00 72 00 61 00 74 00 65 00 20 00 76 00 61 00 75 00 6c 00 74 00 73 00 } //1 [ERROR] Unable to enumerate vaults
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}