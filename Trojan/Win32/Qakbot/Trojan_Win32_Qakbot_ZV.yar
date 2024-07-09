
rule Trojan_Win32_Qakbot_ZV{
	meta:
		description = "Trojan:Win32/Qakbot.ZV,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 06 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {d0 07 00 00 } //5
		$a_03_2 = {a0 0f 00 00 90 09 02 00 81 } //5
		$a_03_3 = {d0 07 00 00 90 09 02 00 81 } //5
		$a_03_4 = {70 17 00 00 90 09 02 00 81 } //5
		$a_03_5 = {f7 04 84 ff 90 09 04 00 c7 45 ?? 00 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5+(#a_03_3  & 1)*5+(#a_03_4  & 1)*5+(#a_03_5  & 1)*5) >=26
 
}