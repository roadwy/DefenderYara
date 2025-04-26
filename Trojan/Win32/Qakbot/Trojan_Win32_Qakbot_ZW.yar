
rule Trojan_Win32_Qakbot_ZW{
	meta:
		description = "Trojan:Win32/Qakbot.ZW,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {0f af 81 44 06 00 00 } //5
		$a_01_2 = {f6 80 98 18 00 00 82 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=11
 
}