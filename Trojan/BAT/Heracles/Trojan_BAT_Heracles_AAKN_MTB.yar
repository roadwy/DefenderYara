
rule Trojan_BAT_Heracles_AAKN_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AAKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {72 21 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 02 28 ?? 00 00 06 2a } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {58 00 42 00 32 00 6a 00 35 00 47 00 77 00 76 00 36 00 66 00 74 00 72 00 59 00 73 00 2b 00 79 00 61 00 65 00 6b 00 54 00 7a 00 47 00 4e 00 68 00 4f 00 44 00 6e 00 53 00 4e 00 5a 00 6b 00 62 00 49 00 47 00 2b 00 77 00 73 00 78 00 54 00 37 00 77 00 4d 00 49 00 3d 00 } //1 XB2j5Gwv6ftrYs+yaekTzGNhODnSNZkbIG+wsxT7wMI=
		$a_01_3 = {46 00 72 00 61 00 6e 00 63 00 69 00 61 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Francia.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}