
rule Trojan_Win32_VB_TI{
	meta:
		description = "Trojan:Win32/VB.TI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 85 40 ff ff ff 8d 55 cc 52 8d 55 d0 8b 08 52 8d 55 ec 52 50 ff 51 30 85 c0 db e2 } //1
		$a_03_1 = {52 c7 85 5c ff ff ff 01 00 00 00 c7 85 54 ff ff ff 02 00 00 00 e8 ?? ?? 00 00 8b 8d ?? ff ff ff 8b 95 ?? ff ff ff 83 ec 10 89 45 a0 8b c4 c7 45 98 08 20 00 00 6a 01 89 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}