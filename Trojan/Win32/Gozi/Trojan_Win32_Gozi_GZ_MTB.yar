
rule Trojan_Win32_Gozi_GZ_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c8 66 89 4d 90 01 01 a1 90 01 04 8b 0d 90 01 04 8d 44 01 90 01 01 a2 90 01 04 0f b7 45 90 01 01 83 e8 0e 2b 45 90 01 01 03 05 90 01 04 a3 90 01 04 a1 90 01 04 2d 90 01 04 0f b6 0d 90 01 04 2b c1 a2 90 01 04 ff 25 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}