
rule Trojan_BAT_LummaStealer_G_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 bd 02 3c 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 3d 00 00 00 83 00 00 00 6b 03 00 00 70 05 } //2
		$a_01_1 = {5f 63 72 79 70 74 65 64 } //1 _crypted
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}