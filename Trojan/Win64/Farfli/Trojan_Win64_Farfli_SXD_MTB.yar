
rule Trojan_Win64_Farfli_SXD_MTB{
	meta:
		description = "Trojan:Win64/Farfli.SXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 04 00 00 "
		
	strings :
		$a_03_0 = {34 aa 88 44 19 04 88 84 19 ?? ?? ?? ?? 48 ff c1 48 8d 05 ?? ?? ?? ?? 8a 04 01 84 c0 75 e2 } //20
		$a_01_1 = {8b c8 41 b8 01 00 00 00 8b d8 41 0f 95 c6 f7 d9 48 8b ce 1a d2 80 c2 df 88 95 } //10
		$a_80_2 = {5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c } //\Chrome\User Data\Default\  1
		$a_80_3 = {5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c } //\Edge\User Data\Default\  1
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=32
 
}