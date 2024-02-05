
rule Trojan_Win32_Manuscrypt_RPN_MTB{
	meta:
		description = "Trojan:Win32/Manuscrypt.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 fc c6 45 f4 53 c6 45 f5 48 c6 45 f6 45 c6 45 f7 4c c6 45 f8 4c c6 45 f9 33 c6 45 fa 32 c6 45 fb 00 } //01 00 
		$a_01_1 = {c6 45 c4 43 c6 45 c5 6f c6 45 c6 43 c6 45 c7 72 c6 45 c8 65 c6 45 c9 61 c6 45 ca 74 c6 45 cb 65 c6 45 cc 49 c6 45 cd 6e c6 45 ce 73 c6 45 cf 74 c6 45 d0 61 c6 45 d1 6e c6 45 d2 63 c6 45 d3 65 } //00 00 
	condition:
		any of ($a_*)
 
}