
rule Trojan_Win32_Fauppod_AQ_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 89 e5 8a 45 0c 8a 4d 08 b2 01 88 cc 02 25 } //3
		$a_01_1 = {ff d0 83 ec 04 b9 f6 ff ff ff 25 01 00 00 00 3d 00 00 00 00 89 4d f4 0f 85 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}