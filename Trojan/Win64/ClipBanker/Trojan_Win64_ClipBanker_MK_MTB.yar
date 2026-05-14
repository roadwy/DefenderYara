
rule Trojan_Win64_ClipBanker_MK_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 7d 1f 0f 48 8d 55 07 48 8d 4d e7 48 0f 47 55 07 48 83 fe 0f 48 0f 47 cb 4c 3b 45 17 } //20
		$a_01_1 = {48 8b d7 4c 8d 05 73 ac 02 00 83 e2 3f 48 8b cf 48 c1 f9 06 48 8d 14 d2 49 8b 0c c8 c6 44 d1 38 00 } //15
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}
rule Trojan_Win64_ClipBanker_MK_MTB_2{
	meta:
		description = "Trojan:Win64/ClipBanker.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c9 66 0f 7f 8d ?? ?? ?? 00 4c 89 bd ?? ?? ?? 00 66 0f 7f 85 ?? ?? ?? 00 4c 8d 0d ?? 28 02 00 4c 8d 05 } //20
		$a_01_1 = {66 69 72 65 66 6f 78 2e 65 78 65 } //15 firefox.exe
		$a_01_2 = {62 72 6f 77 73 65 72 2e 64 6c 6c } //10 browser.dll
		$a_01_3 = {2d 2d 64 69 73 61 62 6c 65 2d 68 74 74 70 32 20 2d 2d 75 73 65 2d 73 70 64 79 3d 6f 66 66 20 2d 2d 64 69 73 61 62 6c 65 2d 71 75 69 63 } //5 --disable-http2 --use-spdy=off --disable-quic
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*15+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5) >=50
 
}