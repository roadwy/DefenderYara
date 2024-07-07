
rule Trojan_Win32_Azorult_RWB_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 ff f9 a8 d5 6a 0f 8c 90 01 04 8b 35 90 01 04 8b 3d 90 01 04 8b 1d 90 01 04 33 c9 89 4d 90 01 01 81 f9 fa 03 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}