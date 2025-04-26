
rule Trojan_Win32_Zegost_CJ_bit{
	meta:
		description = "Trojan:Win32/Zegost.CJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 10 b9 fe 00 00 00 25 ff 00 00 00 89 65 f0 99 f7 f9 c7 45 ec 00 00 00 00 80 c2 58 88 55 13 } //1
		$a_01_1 = {8b 45 08 8a 4d 13 8a 10 32 d1 02 d1 88 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}