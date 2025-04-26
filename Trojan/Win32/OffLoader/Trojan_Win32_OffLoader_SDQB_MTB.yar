
rule Trojan_Win32_OffLoader_SDQB_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SDQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_81_0 = {2f 63 6f 6e 6e 65 63 74 2e 76 61 73 65 62 6f 78 2e 61 72 74 2f 70 65 2f 73 74 61 72 74 2f 69 6e 64 65 78 2e 70 68 70 } //2 /connect.vasebox.art/pe/start/index.php
		$a_81_1 = {2f 73 69 6c 65 6e 74 } //1 /silent
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}