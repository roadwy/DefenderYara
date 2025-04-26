
rule Trojan_Win32_Emotet_ST_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 f8 33 c0 42 81 e2 [0-04] 89 55 f8 8b 4d f8 8a 84 0d e4 fe ff ff 89 45 f0 33 c0 8b 55 f4 03 55 f0 81 e2 ff 00 00 00 89 55 f4 8b 4d f4 8a 84 0d e4 fe ff ff 89 45 ec 8b 4d f8 8a 55 ec 88 94 0d e4 fe ff ff 8b 55 f4 8a 45 f0 88 84 15 e4 fe ff ff 33 c0 8a 4d f0 02 4d ec 8a c1 8b 4d 08 8a 94 05 e4 fe ff ff 8b 45 fc 30 14 01 ff 45 fc 8b 55 fc 3b 55 0c 7c } //1
		$a_02_1 = {8b c3 bf 0a 00 00 00 99 f7 ff 80 c2 ?? 33 c0 8a c1 88 14 06 8b c3 bb 0a 00 00 00 99 f7 fb 8b d8 49 85 db 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}