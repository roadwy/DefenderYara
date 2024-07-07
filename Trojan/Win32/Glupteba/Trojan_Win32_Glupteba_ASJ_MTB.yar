
rule Trojan_Win32_Glupteba_ASJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 0c 30 83 bc 24 90 01 02 00 00 0f 75 51 6a 00 6a 00 6a 00 ff d7 90 00 } //2
		$a_01_1 = {ff d7 81 fe 1e a0 01 00 7e 08 81 fb d7 be f5 00 75 09 46 81 fe 52 7a ce 1e } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}