
rule Trojan_Win32_MyDoom_RF_MTB{
	meta:
		description = "Trojan:Win32/MyDoom.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c1 29 d9 83 c1 0d b8 4f ec c4 4e f7 e9 c1 fa 03 89 c8 c1 f8 1f 29 c2 8d 04 52 8d 04 82 01 c0 29 c1 0f be 54 29 d8 eb 42 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}