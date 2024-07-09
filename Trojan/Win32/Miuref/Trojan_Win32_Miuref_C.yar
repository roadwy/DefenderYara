
rule Trojan_Win32_Miuref_C{
	meta:
		description = "Trojan:Win32/Miuref.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 46 04 03 c1 74 ?? 6a ff 6a 01 57 ff d0 } //1
		$a_01_1 = {0f b7 0a 8b d9 81 e3 00 f0 ff ff 81 fb 00 30 00 00 75 0d 8b 5d 08 81 e1 ff 0f 00 00 03 cf 01 19 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}