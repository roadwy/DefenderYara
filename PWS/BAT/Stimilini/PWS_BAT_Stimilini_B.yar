
rule PWS_BAT_Stimilini_B{
	meta:
		description = "PWS:BAT/Stimilini.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 73 00 74 00 65 00 61 00 6d 00 5c 00 53 00 68 00 65 00 6c 00 6c 00 5c 00 4f 00 70 00 65 00 6e 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 00 00 } //1
		$a_01_1 = {09 73 00 73 00 66 00 6e 00 00 } //1
		$a_01_2 = {31 00 2e 00 72 00 61 00 72 00 00 11 63 00 6f 00 6e 00 66 00 69 00 67 00 2f 00 2f 00 } //1 1.rarᄀconfig//
		$a_01_3 = {2e 00 70 00 68 00 70 00 00 09 50 00 4f 00 53 00 54 00 00 0d 63 00 6f 00 6e 00 66 00 69 00 67 00 } //1 .phpऀPOSTഀconfig
		$a_01_4 = {47 65 74 53 74 65 61 6d 50 61 74 68 00 53 65 6e 64 46 69 6c 65 73 00 63 6c 69 65 6e 74 5f 55 70 } //1 敇却整浡慐桴匀湥䙤汩獥挀楬湥彴灕
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}