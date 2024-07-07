
rule Trojan_Win32_InfoStealer_E_MTB{
	meta:
		description = "Trojan:Win32/InfoStealer.E!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {76 61 75 6c 74 63 6c 69 2e 64 6c 6c } //1 vaultcli.dll
		$a_01_1 = {70 61 73 73 66 66 2e 74 61 72 } //3 passff.tar
		$a_01_2 = {63 6f 6f 6b 69 65 2e 74 61 72 } //3 cookie.tar
		$a_01_3 = {69 00 65 00 5f 00 76 00 61 00 75 00 6c 00 74 00 } //1 ie_vault
		$a_01_4 = {4c 00 6f 00 67 00 6f 00 6e 00 54 00 72 00 69 00 67 00 67 00 65 00 72 00 } //1 LogonTrigger
		$a_01_5 = {6d 00 61 00 69 00 6c 00 5f 00 76 00 61 00 75 00 6c 00 74 00 } //1 mail_vault
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}