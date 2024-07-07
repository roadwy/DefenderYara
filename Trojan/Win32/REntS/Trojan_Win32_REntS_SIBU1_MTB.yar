
rule Trojan_Win32_REntS_SIBU1_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIBU1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 ca 4f be 90 01 04 8a 11 41 84 d2 74 90 01 01 90 02 0a 0f be d2 8d 49 01 33 d6 69 f2 90 01 04 8a 51 ff 84 d2 75 90 01 01 81 fe 90 01 04 90 18 8b 75 90 01 01 8b 55 90 01 01 ff 75 90 01 01 8b 46 24 8d 04 78 0f b7 0c 10 8b 46 1c 8d 04 88 8b 04 10 03 c2 ff d0 90 00 } //1
		$a_03_1 = {2b d0 89 95 90 01 04 1b f1 89 b5 90 01 04 8b b5 90 1b 00 8b 95 90 1b 01 8b 8d 90 01 04 8b 85 90 01 04 50 51 52 56 e8 90 01 04 89 45 90 01 01 89 55 90 01 01 8b 4d 90 1b 07 8b 45 90 1b 08 30 0c 1f 43 3b 5d 90 01 01 73 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}