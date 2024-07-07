
rule Trojan_Win32_Tibs_JJ{
	meta:
		description = "Trojan:Win32/Tibs.JJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 ff ff 00 00 0f ae 14 24 58 6a 00 0f ae 1c 24 58 40 8d b0 } //1
		$a_01_1 = {c6 45 ec 6b c6 45 ed 00 c6 45 ee 65 c6 45 ef 00 c6 45 f0 72 c6 45 f1 00 c6 45 f2 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}