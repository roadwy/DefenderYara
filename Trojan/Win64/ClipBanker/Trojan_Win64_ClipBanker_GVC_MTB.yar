
rule Trojan_Win64_ClipBanker_GVC_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.GVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c9 ff 15 89 39 02 00 85 c0 0f 84 25 03 00 00 b9 01 00 00 00 ff 15 7e 39 02 00 48 8b d8 48 85 c0 0f 84 07 03 00 00 48 8b c8 ff 15 21 36 02 00 48 85 c0 0f 84 f5 02 00 00 } //2
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}