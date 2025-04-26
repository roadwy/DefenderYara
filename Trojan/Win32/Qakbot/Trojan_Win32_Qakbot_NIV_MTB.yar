
rule Trojan_Win32_Qakbot_NIV_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.NIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 01 83 c1 04 8b f8 c1 ef 10 81 e7 ff 00 00 00 8b 3c bd 38 78 0a 4d 8b d8 c1 eb 08 81 e3 ff 00 00 00 33 3c 9d 38 7c 0a 4d 8b d8 c1 eb 18 33 3c 9d 38 74 0a 4d 25 ff 00 00 00 33 3c 85 38 80 0a 4d 83 ee 04 83 ea 01 8b c7 75 b5 } //1
		$a_01_1 = {70 72 69 6e 74 } //1 print
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}