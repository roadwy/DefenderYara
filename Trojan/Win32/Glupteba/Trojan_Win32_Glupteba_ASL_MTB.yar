
rule Trojan_Win32_Glupteba_ASL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 0c 30 83 bc 24 90 01 02 00 00 0f 75 90 00 } //2
		$a_03_1 = {51 53 ff 15 90 01 02 40 00 53 53 e8 90 01 02 ff ff 53 53 e8 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}