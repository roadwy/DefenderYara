
rule Trojan_WinNT_Bibei_A{
	meta:
		description = "Trojan:WinNT/Bibei.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {25 03 00 00 80 79 ?? 48 83 c8 fc 40 89 45 fc 8b 45 10 99 b9 ff 00 00 00 f7 f9 88 55 ef 8b 55 08 89 55 f4 c7 45 f8 00 00 00 00 } //1
		$a_02_1 = {0f b7 55 f0 a1 ?? ?? ?? ?? 8b 08 8b 14 91 89 15 ?? ?? ?? ?? fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 0f b7 45 f0 8b 0d ?? ?? ?? ?? 8b 11 c7 04 82 ?? ?? ?? ?? 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}