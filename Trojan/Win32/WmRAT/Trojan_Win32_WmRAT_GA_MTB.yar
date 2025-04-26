
rule Trojan_Win32_WmRAT_GA_MTB{
	meta:
		description = "Trojan:Win32/WmRAT.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 64 ff d6 6a 01 e8 ?? ?? ?? ?? 83 c4 04 3b c7 } //1
		$a_02_1 = {88 19 4a 41 47 4e 85 d2 ?? ?? 5f 49 5e b8 7a 00 07 80 } //1
		$a_02_2 = {6a 00 b8 04 00 00 00 2b c6 50 8d 0c 3e 51 52 ff ?? 83 f8 ff ?? ?? 03 f0 83 fe 04 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*2) >=3
 
}