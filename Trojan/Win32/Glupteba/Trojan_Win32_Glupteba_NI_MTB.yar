
rule Trojan_Win32_Glupteba_NI_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 f0 8b 85 90 02 04 03 90 02 03 33 90 02 03 33 90 02 03 2b 90 02 03 81 3d 90 02 04 17 04 00 00 90 18 81 90 02 09 ff 90 02 05 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}