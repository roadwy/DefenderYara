
rule Trojan_Win32_RegPersist_ZA_MTB{
	meta:
		description = "Trojan:Win32/RegPersist.ZA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 00 4b 00 4c 00 4d 00 5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_1 = {2e 00 65 00 78 00 65 00 20 00 2d 00 2d 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 .exe --password
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}