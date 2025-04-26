
rule Trojan_Win32_Emotet_DHV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {c1 c8 0d 80 f9 61 0f b6 c9 72 03 83 e9 20 03 c1 42 8a 0a 84 c9 75 e9 } //1
		$a_00_1 = {6a 40 68 00 10 00 00 8d 45 f0 50 56 8d 45 f8 50 ff 55 bc 50 ff 55 b8 ff 75 0c ff 75 08 ff 75 f8 ff 55 d8 83 c4 0c ff 75 0c 8d 45 0c 50 ff 75 f8 56 6a 01 56 ff 75 ec ff 55 dc f7 d8 1b c0 23 45 f8 } //1
		$a_02_2 = {83 c4 40 ff 35 ?? ?? ?? ?? 8d 45 f0 ff 35 ?? ?? ?? ?? 50 53 8d 45 f8 50 ff 55 bc 50 ff 55 b8 ff 75 0c ff 75 08 ff 75 f8 ff 55 d8 57 56 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}