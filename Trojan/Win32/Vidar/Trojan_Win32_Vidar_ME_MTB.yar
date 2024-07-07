
rule Trojan_Win32_Vidar_ME_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 85 0c ff ff ff 89 85 0c ff ff ff 8b 85 10 ff ff ff 33 85 08 ff ff ff 89 85 08 ff ff ff c6 85 b9 fd ff ff 00 8b 85 d4 fd ff ff 8b 40 54 89 85 14 ff ff ff 8b 85 14 ff ff ff 03 85 f0 fe ff ff 89 85 18 ff ff ff 8b 85 18 ff ff ff 8b 00 8b 95 08 ff ff ff 3b c2 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}