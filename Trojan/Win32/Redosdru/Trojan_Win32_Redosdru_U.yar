
rule Trojan_Win32_Redosdru_U{
	meta:
		description = "Trojan:Win32/Redosdru.U,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 50 72 6f 67 72 61 7e 31 5c 25 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 25 5c [0-05] 2e 56 42 53 } //1
		$a_03_1 = {55 ff d7 50 ff d3 8b f8 56 ff 74 24 ?? ff d7 85 c0 74 ?? ff 74 24 ?? 8d 46 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75 e3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}