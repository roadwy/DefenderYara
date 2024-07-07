
rule Trojan_Win32_Qbot_PAP_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 3b 2a cf 62 70 ae 5c b8 f3 f6 2b 9d b7 d1 03 77 9e 30 32 69 3e 33 38 fd fb f0 e8 a2 db e0 d0 14 2e ab 19 7d 74 d1 9f 3c c5 92 44 a1 67 84 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}