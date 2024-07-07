
rule Trojan_Win64_Bumblebee_WEJ_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.WEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 43 89 14 86 41 0f b6 03 4c 8b 47 90 01 01 0f b7 4c 45 90 01 01 41 8b c1 99 45 03 cd f7 f9 43 0f b6 04 03 4d 03 dd 66 03 d0 66 42 31 14 43 4c 8b 84 24 90 01 04 45 3b cc 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}