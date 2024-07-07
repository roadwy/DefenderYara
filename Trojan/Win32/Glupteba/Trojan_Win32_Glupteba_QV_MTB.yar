
rule Trojan_Win32_Glupteba_QV_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 5d 74 89 90 02 05 89 90 02 05 8b 90 02 05 29 90 02 02 81 3d 90 02 08 90 18 8b 90 02 05 29 90 02 02 ff 90 02 05 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}