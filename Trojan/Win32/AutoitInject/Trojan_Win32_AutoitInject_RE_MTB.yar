
rule Trojan_Win32_AutoitInject_RE_MTB{
	meta:
		description = "Trojan:Win32/AutoitInject.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {27 a7 1e 6e 01 05 ca 6f 25 67 0c 03 cb c3 65 5a 5d 4b 3e e7 d3 50 21 93 ef 5c fd 8c 0f 33 06 7b } //01 00 
		$a_01_1 = {97 87 3c b4 33 40 9e 6a 97 71 27 c1 e9 4f fd ae 03 4f 4b 82 88 e1 71 ea a1 3d 7f 5a 80 4c 2e f5 } //00 00 
	condition:
		any of ($a_*)
 
}