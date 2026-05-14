
rule Trojan_Win32_Zusy_LRA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {30 84 0d 69 fb ff ff 41 83 f9 12 72 ?? c6 85 7b fb ff ff 00 b1 07 c7 85 94 fb ff ff 07 6c 62 75 33 c0 c7 85 98 fb ff ff 69 62 6b 34 c7 85 9c fb ff ff 35 29 63 6b 66 c7 85 a0 fb ff ff 6b 00 } //20
		$a_03_1 = {8d 85 49 fd ff ff 30 14 08 41 83 f9 0d 73 ?? 8a 95 48 fd ff ff } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}