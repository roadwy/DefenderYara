
rule Trojan_Win32_Redosdru_U{
	meta:
		description = "Trojan:Win32/Redosdru.U,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 50 72 6f 67 72 61 7e 31 5c 25 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 25 5c 90 02 05 2e 56 42 53 90 00 } //1
		$a_03_1 = {55 ff d7 50 ff d3 8b f8 56 ff 74 24 90 01 01 ff d7 85 c0 74 90 01 01 ff 74 24 90 01 01 8d 46 90 01 01 50 ff 15 90 01 04 85 c0 75 e3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}