
rule Trojan_Win32_Glupteba_ASK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 14 30 83 ff 0f 75 } //2
		$a_01_1 = {3d cb d9 0b 00 75 06 81 c1 00 00 00 00 40 3d 3d a6 15 00 7c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}