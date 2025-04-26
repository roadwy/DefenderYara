
rule Trojan_Win64_Zebracon_B_dha{
	meta:
		description = "Trojan:Win64/Zebracon.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 79 00 6e 00 61 00 63 00 6f 00 72 00 2e 00 20 00 49 00 6e 00 63 00 2e 00 } //1 Synacor. Inc.
		$a_01_1 = {5a 00 69 00 6d 00 62 00 72 00 61 00 20 00 53 00 6f 00 61 00 70 00 } //1 Zimbra Soap
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}