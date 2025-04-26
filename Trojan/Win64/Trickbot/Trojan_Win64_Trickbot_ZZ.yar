
rule Trojan_Win64_Trickbot_ZZ{
	meta:
		description = "Trojan:Win64/Trickbot.ZZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5f 48 8b f1 48 33 c0 68 58 02 00 00 59 50 e2 fd 48 8b c7 57 48 8b ec 48 05 0b 30 00 00 48 89 45 08 48 89 75 40 68 f0 ff 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}