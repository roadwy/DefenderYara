
rule Trojan_Win32_Pony_AQ_MTB{
	meta:
		description = "Trojan:Win32/Pony.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {d2 6c 6a 47 52 30 a6 0d 48 b5 c8 86 b2 cf 7c b1 6d 45 b3 bc ed 61 8d e1 c6 86 28 3c 0c 1c f9 86 7b 73 4c 05 3b 4a dc 5e 14 63 fc ef 7e } //2
		$a_01_1 = {21 81 1b 55 ae 4d ef 25 04 5f 0c f5 30 45 96 fb 53 f8 40 eb } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}