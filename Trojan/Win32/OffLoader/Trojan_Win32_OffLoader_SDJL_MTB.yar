
rule Trojan_Win32_OffLoader_SDJL_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SDJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 7a 00 6f 00 6f 00 73 00 63 00 68 00 6f 00 6f 00 6c 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 70 00 65 00 2f 00 73 00 74 00 61 00 72 00 74 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 } //2 /zooschool.website/pe/start/index.php
		$a_01_1 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}