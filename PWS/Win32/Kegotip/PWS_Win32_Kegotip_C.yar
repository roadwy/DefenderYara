
rule PWS_Win32_Kegotip_C{
	meta:
		description = "PWS:Win32/Kegotip.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 4d 53 57 51 2a 2e 74 6d 70 00 } //1
		$a_01_1 = {54 75 72 62 6f 46 54 50 5c 61 64 64 72 62 6b 2e 64 61 74 00 } //1
		$a_03_2 = {83 e2 10 74 ?? 0f be 85 ?? ?? ff ff 83 f8 2e 75 22 0f be 8d ?? ?? ff ff 85 c9 74 ?? 0f be 95 ?? ?? ff ff 83 fa 2e 75 0b 0f be 85 ?? ?? ff ff 85 c0 74 ?? 68 04 01 00 00 8b 4d 08 51 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}