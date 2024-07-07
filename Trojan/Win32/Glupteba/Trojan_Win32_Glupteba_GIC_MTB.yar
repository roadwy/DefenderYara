
rule Trojan_Win32_Glupteba_GIC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 83 c4 04 e8 90 01 04 29 ff 81 c7 90 01 04 31 02 42 39 f2 75 e1 21 cf 90 00 } //10
		$a_03_1 = {5b 29 f6 29 d2 e8 90 01 04 31 1f 47 21 f6 39 cf 75 90 01 01 c3 21 d2 8d 1c 18 46 21 d6 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}