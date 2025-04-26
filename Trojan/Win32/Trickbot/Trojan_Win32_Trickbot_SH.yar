
rule Trojan_Win32_Trickbot_SH{
	meta:
		description = "Trojan:Win32/Trickbot.SH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 70 28 ff 70 24 ff 70 20 ff 70 1c ff 70 18 ff 70 14 ff 70 10 ff 70 0c ff 70 08 ff 10 } //1
		$a_01_1 = {ff 76 04 ff 36 ff 56 0c ff 76 04 ff 56 14 ff 36 ff 56 14 89 7e 04 89 3e 57 ff 56 1c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}