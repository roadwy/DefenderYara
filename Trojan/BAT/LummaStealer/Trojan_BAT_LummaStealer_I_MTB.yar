
rule Trojan_BAT_LummaStealer_I_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {06 02 8e 69 fe 04 } //2
		$a_01_1 = {06 17 58 0a 08 } //2
		$a_01_2 = {02 06 02 06 91 66 d2 9c } //2
		$a_01_3 = {5f 61 70 70 64 61 74 61 } //4 _appdata
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*4) >=10
 
}