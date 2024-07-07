
rule Trojan_Win32_TrickBotCrypt_FJ_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b ca 2b 0d 90 01 04 2b 0d 90 01 04 8b 55 08 0f b6 0c 0a 8b 55 0c 0f b6 04 02 33 c1 8b 4d f4 2b 0d 90 01 04 03 0d 90 01 04 03 0d 90 01 04 2b 0d 90 01 04 03 0d 90 01 04 03 0d 90 01 04 2b 0d 90 01 04 2b 0d 90 01 04 03 0d 90 01 04 03 0d 90 01 04 2b 0d 90 01 04 2b 0d 90 01 04 8b 55 0c 88 04 0a 90 00 } //1
		$a_81_1 = {79 25 28 38 72 77 4f 77 6b 30 31 53 4f 58 3e 74 42 41 29 5f 28 79 73 35 3c 62 32 34 32 28 6d 62 78 4b 5e 25 2a 54 2a 2a 45 73 51 49 75 37 75 76 6d 37 3e 68 2b 45 59 42 33 6f 42 66 4a 26 73 3f 42 5a 51 6f 54 77 65 45 78 21 42 6c 52 4c 4c 24 6a 51 38 6f 24 23 72 32 78 31 32 73 46 5e 75 63 21 48 73 64 3f 6d 2a 53 47 62 46 61 } //1 y%(8rwOwk01SOX>tBA)_(ys5<b242(mbxK^%*T**EsQIu7uvm7>h+EYB3oBfJ&s?BZQoTweEx!BlRLL$jQ8o$#r2x12sF^uc!Hsd?m*SGbFa
		$a_81_2 = {26 58 2b 45 2a 74 63 61 33 54 45 76 68 30 42 50 4f 4d 37 2b 6d 2a 4e 4d 32 2a 76 55 6f 59 67 2a 7a 6b 3c 49 3c 6d 5a 7a 3f 77 6d 73 2a 21 68 36 57 75 56 34 63 48 50 42 66 44 43 7a 70 41 28 65 50 63 52 5e 5f 2a 65 3f 73 3c 63 76 71 2a 52 5e 6b 79 68 4f 44 48 45 44 68 45 5a 55 4b 6a 2a 58 4b 66 23 78 50 31 63 49 51 5a 58 63 23 5f 53 50 65 43 48 34 } //1 &X+E*tca3TEvh0BPOM7+m*NM2*vUoYg*zk<I<mZz?wms*!h6WuV4cHPBfDCzpA(ePcR^_*e?s<cvq*R^kyhODHEDhEZUKj*XKf#xP1cIQZXc#_SPeCH4
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}