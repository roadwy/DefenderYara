
rule Trojan_Win32_Lokibot_DTY_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.DTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6c 65 4f 70 65 6e 00 f7 00 5f 5f 76 62 61 4e 65 77 32 00 a9 01 5f 61 64 6a 5f 66 64 69 76 5f 6d 33 32 69 00 00 ae 01 5f 61 64 6a 5f 66 64 69 76 72 5f 6d 33 32 69 00 ad 01 5f 61 64 6a 5f 66 64 69 76 72 5f 6d 33 32 00 00 ab 01 5f 61 64 6a 5f 66 64 69 76 5f 72 00 cf 00 5f 5f 76 62 61 49 34 56 61 72 00 00 62 01 5f 5f 76 62 61 56 61 72 44 75 70 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}