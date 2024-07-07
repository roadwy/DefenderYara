
rule Trojan_Win32_Bunitu_RPI_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 89 85 30 fe ff ff 8b 4d f4 03 8d 30 fe ff ff 0f b6 11 89 95 34 fe ff ff 8b 45 ec 03 85 30 fe ff ff 8a 8d 34 fe ff ff 88 08 8b 55 f8 83 c2 01 89 55 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}