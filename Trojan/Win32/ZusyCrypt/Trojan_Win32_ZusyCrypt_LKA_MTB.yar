
rule Trojan_Win32_ZusyCrypt_LKA_MTB{
	meta:
		description = "Trojan:Win32/ZusyCrypt.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 64 6f 77 73 5c 63 61 63 68 65 5c 6d 67 72 2e 76 62 73 } //1 windows\cache\mgr.vbs
		$a_01_1 = {66 74 70 2e 66 6f 72 65 73 74 2d 66 69 72 65 2e 6e 65 74 } //1 ftp.forest-fire.net
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}