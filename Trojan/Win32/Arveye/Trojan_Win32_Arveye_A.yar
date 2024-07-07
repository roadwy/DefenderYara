
rule Trojan_Win32_Arveye_A{
	meta:
		description = "Trojan:Win32/Arveye.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 ff 01 0f 00 50 ff 15 08 60 40 00 85 c0 0f 95 c3 eb b4 cc 8b 44 24 04 69 c0 e8 03 00 00 50 ff 15 28 60 40 00 } //1
		$a_01_1 = {e8 c9 ff ff ff 8d 44 24 0c 68 54 61 40 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}