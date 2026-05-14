
rule Trojan_BAT_Zusy_KK_MTB{
	meta:
		description = "Trojan:BAT/Zusy.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 62 62 36 65 37 30 32 65 2d 34 31 34 65 2d 34 30 31 61 2d 39 61 63 39 2d 66 36 31 32 35 35 36 37 63 65 37 66 } //10 $bb6e702e-414e-401a-9ac9-f6125567ce7f
		$a_01_1 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //2 get_Assembly
		$a_01_2 = {52 75 6e 6e 65 72 5f 41 } //1 Runner_A
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=13
 
}