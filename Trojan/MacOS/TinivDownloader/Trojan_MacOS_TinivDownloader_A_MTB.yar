
rule Trojan_MacOS_TinivDownloader_A_MTB{
	meta:
		description = "Trojan:MacOS/TinivDownloader.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {28 00 00 90 08 61 2d 91 29 00 00 90 29 61 33 91 a0 83 1f f8 a1 03 1f f8 a2 f3 1e 38 29 01 40 f9 01 01 40 f9 e0 03 09 aa df 08 00 94 28 00 00 90 08 81 0a 91 09 00 80 d2 21 00 00 90 21 80 2d 91 21 00 40 f9 e2 03 08 aa e3 03 09 aa d6 08 00 94 28 00 00 90 08 a1 2d 91 29 00 00 90 29 81 33 91 a0 03 1e f8 29 01 40 f9 a2 03 5e f8 01 01 40 f9 e0 03 09 aa cc 08 00 94 28 00 00 90 08 01 0b 91 } //1
		$a_00_1 = {59 4b 41 34 53 47 59 41 4e 37 } //1 YKA4SGYAN7
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}