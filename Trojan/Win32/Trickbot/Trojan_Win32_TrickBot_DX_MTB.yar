
rule Trojan_Win32_TrickBot_DX_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f8 00 00 00 2b 90 02 12 6b 90 01 01 29 8b 90 01 01 c1 e2 06 90 02 04 8b 54 90 01 01 3c 90 02 04 2b 90 01 01 8b 90 01 02 78 03 90 02 03 8b 90 02 02 24 8b 90 02 02 20 90 02 04 8d 90 02 08 8b 90 01 01 1c 8b 90 01 01 18 90 02 08 03 90 01 01 03 90 01 01 03 90 01 01 03 90 00 } //1
		$a_03_1 = {55 8b ec 8b 90 02 15 c1 90 01 01 0d 3c 61 0f be c0 7c 03 83 e8 20 90 02 04 03 90 02 04 8a 90 01 01 84 c0 75 ea 8d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}