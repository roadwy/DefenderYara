
rule Trojan_BAT_Nebula_NN_MTB{
	meta:
		description = "Trojan:BAT/Nebula.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {2d 04 14 0d de 2c 07 6f 9c 00 00 0a d4 8d 3d 00 00 01 0c 07 08 16 08 8e 69 6f 9d 00 00 0a 26 08 28 9e 00 00 0a 0d } //2
		$a_01_1 = {4e 65 62 75 6c 61 53 74 65 61 6c 65 72 2e 65 78 65 } //1 NebulaStealer.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}