
rule Trojan_Win32_Zudochaka_RPX_MTB{
	meta:
		description = "Trojan:Win32/Zudochaka.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 8b 45 e4 8b 10 ff 12 03 45 c4 50 6a 00 ff 55 a4 89 45 e0 8b 45 ac 2d 5f 0a 00 00 50 8b 45 b0 2d e3 04 00 00 50 8b 45 e4 8b 10 ff 12 03 45 c4 50 } //1
		$a_01_1 = {2b d8 8b 45 d8 31 18 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 72 b1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}