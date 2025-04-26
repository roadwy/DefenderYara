
rule Trojan_Win32_Zbot_BAF_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 02 83 c2 04 f7 d8 8d 40 d7 83 e8 02 83 c0 01 29 d8 89 c3 6a 00 8f 07 01 47 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_Win32_Zbot_BAF_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 8d ac fd ff ff 0f be 91 [0-04] 8b 85 a4 fc ff ff 03 85 d0 fd ff ff 33 d0 8b 8d ac fd ff ff 88 91 [0-04] ba 7d 22 00 00 85 d2 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}