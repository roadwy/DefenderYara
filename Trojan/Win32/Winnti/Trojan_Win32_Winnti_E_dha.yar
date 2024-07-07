
rule Trojan_Win32_Winnti_E_dha{
	meta:
		description = "Trojan:Win32/Winnti.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {62 61 73 5f 5f 2e 66 6f 6e 90 02 05 66 6f 6e 74 73 5c 90 02 10 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 90 02 10 53 43 53 49 44 49 53 4b 90 02 10 5c 5c 2e 5c 53 63 73 69 25 64 3a 90 00 } //4
		$a_00_1 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 5c 00 54 00 63 00 70 00 69 00 70 00 } //1 \Driver\Tcpip
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*1) >=5
 
}