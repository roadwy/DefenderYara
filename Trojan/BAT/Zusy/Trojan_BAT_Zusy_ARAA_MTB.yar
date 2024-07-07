
rule Trojan_BAT_Zusy_ARAA_MTB{
	meta:
		description = "Trojan:BAT/Zusy.ARAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 41 75 74 6f 54 6f 72 49 50 5c 6f 62 6a 5c 44 65 62 75 67 5c 53 65 63 75 72 53 6f 63 6b 73 2e 70 64 62 } //2 \AutoTorIP\obj\Debug\SecurSocks.pdb
		$a_01_1 = {24 33 31 35 38 66 62 36 34 2d 34 66 31 33 2d 34 62 66 39 2d 61 31 30 64 2d 63 66 37 37 36 61 34 39 31 34 30 66 } //2 $3158fb64-4f13-4bf9-a10d-cf776a49140f
		$a_00_2 = {53 00 65 00 72 00 76 00 65 00 72 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 } //2 ServerStorage
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}