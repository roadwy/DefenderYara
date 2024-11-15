
rule Trojan_BAT_LummaStealer_AYB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4a 75 73 74 41 42 61 63 6b 44 6f 6f 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 4a 75 73 74 41 42 61 63 6b 44 6f 6f 72 2e 70 64 62 } //2 JustABackDoor\obj\Debug\JustABackDoor.pdb
		$a_01_1 = {24 37 38 61 62 66 36 65 34 2d 61 34 64 61 2d 34 34 39 38 2d 38 65 66 66 2d 37 33 38 36 39 32 32 35 66 66 32 37 } //1 $78abf6e4-a4da-4498-8eff-73869225ff27
		$a_01_2 = {4a 75 73 74 41 42 61 63 6b 44 6f 6f 72 2e 45 78 65 63 75 74 6f 72 } //1 JustABackDoor.Executor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}