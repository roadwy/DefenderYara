
rule Trojan_Win64_TinyDow_A_MTB{
	meta:
		description = "Trojan:Win64/TinyDow.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 0f b6 04 0e 43 88 04 08 4d 8d 49 01 84 c0 75 ?? 4c 89 64 24 30 45 33 c9 c7 44 24 28 02 00 00 00 45 33 c0 ba 00 00 00 40 c7 44 24 20 02 00 00 00 49 8b cf ff 15 15 16 00 00 48 8b f8 48 8d 45 80 48 ff c3 44 38 24 18 75 ?? 4c 8b c3 4c 89 64 24 20 4c 8d 4c 24 40 48 8b cf 48 8d 55 80 ff 15 } //2
		$a_01_1 = {73 74 61 72 74 20 2f 6d 69 6e 20 63 6d 64 20 2f 63 } //2 start /min cmd /c
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}