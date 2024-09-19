
rule Trojan_Win32_Smokeloader_PAFB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.PAFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 7c 8b 8d 78 fe ff ff 5f 5e 89 18 89 48 04 } //2
		$a_01_1 = {89 45 70 8b 45 70 8b 95 80 fe ff ff 03 c7 03 d3 33 c2 33 c1 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}