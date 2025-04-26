
rule Trojan_Win32_OffLoader_RDA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 2f 00 67 00 72 00 6f 00 75 00 70 00 63 00 6f 00 62 00 77 00 65 00 62 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 65 00 6c 00 64 00 2e 00 70 00 68 00 70 00 3f 00 } //2 //groupcobweb.online/eld.php?
		$a_01_1 = {73 00 65 00 72 00 76 00 65 00 72 00 5c 00 73 00 68 00 61 00 72 00 65 00 } //1 server\share
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}