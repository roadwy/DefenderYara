
rule Trojan_Win32_GCleaner_BAZ_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.BAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 14 7b 81 02 ee 3d ea f4 89 45 70 8b 85 70 fe ff ff 01 45 70 8b b5 78 fe ff ff 8b 8d 80 fe ff ff 03 8d 78 fe ff ff c1 e6 04 03 b5 64 fe ff ff 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}