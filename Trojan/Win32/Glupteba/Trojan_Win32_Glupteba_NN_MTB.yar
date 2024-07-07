
rule Trojan_Win32_Glupteba_NN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 cf 33 f1 81 3d 90 02 08 89 90 02 03 90 18 90 02 08 33 f0 89 b5 90 02 04 8b 85 90 02 04 29 45 90 02 0a ff 8d 90 02 04 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}