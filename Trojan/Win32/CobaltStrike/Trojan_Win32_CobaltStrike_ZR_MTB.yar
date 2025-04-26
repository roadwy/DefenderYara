
rule Trojan_Win32_CobaltStrike_ZR_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 61 00 72 00 63 00 68 00 69 00 76 00 6f 00 2d 00 70 00 64 00 66 00 31 00 37 00 34 00 2e 00 63 00 6f 00 6d 00 2f 00 77 00 6d 00 32 00 32 00 30 00 33 00 39 00 32 00 38 00 32 00 36 00 35 00 31 00 38 00 36 00 } //1 https://archivo-pdf174.com/wm2203928265186
		$a_01_1 = {7a 00 53 00 72 00 56 00 52 00 6d 00 42 00 66 00 66 00 4e 00 76 00 65 00 46 00 69 00 73 00 5a 00 59 00 55 00 61 00 53 00 78 00 54 00 6d 00 75 00 67 00 76 00 4f 00 72 00 71 00 4b 00 } //1 zSrVRmBffNveFisZYUaSxTmugvOrqK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}