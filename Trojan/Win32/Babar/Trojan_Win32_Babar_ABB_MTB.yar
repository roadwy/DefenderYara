
rule Trojan_Win32_Babar_ABB_MTB{
	meta:
		description = "Trojan:Win32/Babar.ABB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 45 c4 8b 55 f8 03 55 e8 8b 45 f4 89 02 8b 4d f8 03 4d c4 89 4d bc 8b 15 04 80 41 00 89 55 cc 8b 45 f8 03 45 e8 8b 4d 08 89 48 04 8b 55 f8 03 55 e8 89 55 ec 8b 45 ac 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}