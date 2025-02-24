
rule Trojan_BAT_LummaStealer_RDK_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.RDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 36 34 65 65 36 36 65 2d 66 36 30 34 2d 34 38 33 66 2d 62 65 65 65 2d 30 38 30 65 61 64 65 61 35 38 32 33 } //2 a64ee66e-f604-483f-beee-080eadea5823
		$a_01_1 = {64 65 73 69 67 6e 20 6e 65 74 77 6f 72 6b 20 74 68 65 6d 20 67 72 65 65 6e 20 69 6e 6e 6f 76 61 74 65 } //1 design network them green innovate
		$a_01_2 = {63 6f 6d 70 6c 65 78 20 69 6e 74 65 67 72 61 74 65 20 62 75 69 6c 64 20 71 75 69 63 6b 20 73 75 6e 20 75 6e 64 65 72 73 74 61 6e 64 20 6e 65 74 77 6f 72 6b 20 70 6f 77 65 72 20 66 61 73 74 20 73 75 70 70 6f 72 74 } //1 complex integrate build quick sun understand network power fast support
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}