
rule Trojan_Win32_Smokeloader_DKL_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.DKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b c8 c1 e0 08 03 c1 8b c8 c1 e0 10 03 c1 8b ca 83 e2 03 c1 e9 02 74 06 } //10
		$a_80_1 = {56 45 53 55 52 41 47 4f 53 41 47 } //VESURAGOSAG  1
		$a_80_2 = {43 49 44 41 46 49 43 55 44 55 52 4f 53 4f 54 41 52 4f 4d } //CIDAFICUDUROSOTAROM  1
		$a_80_3 = {56 49 44 49 57 41 59 41 50 45 4e 49 47 55 } //VIDIWAYAPENIGU  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}