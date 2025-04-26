
rule Trojan_MacOS_Zako_A_MTB{
	meta:
		description = "Trojan:MacOS/Zako.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 7a 61 6b 6f 2e 63 68 61 74 7a 75 6d 2e 50 61 63 6b 61 67 65 50 6c 75 67 69 6e } //1 com.zako.chatzum.PackagePlugin
		$a_02_1 = {2f 65 79 61 6c 66 69 73 68 6c 65 72 2f 44 6f 63 75 6d 65 6e 74 73 2f 53 6f 75 72 63 65 2f [0-07] 2f 74 6f 6f 6c 62 61 72 73 2f 4d 61 63 2f 6d 61 63 69 6e 73 74 61 6c 6c 65 72 2f [0-07] 2d 54 6f 6f 6c 62 61 72 2d 49 6e 73 74 61 6c 6c 65 72 2d 50 6c 75 67 69 6e 2f 50 61 63 6b 61 67 65 50 6c 75 67 69 6e 2f 50 61 63 6b 61 67 65 50 6c 75 67 69 6e 50 61 6e 65 2e 68 } //1
		$a_02_2 = {63 6f 6d 2e 7a 61 6b 6f 2e [0-07] 2e 70 6b 67 2e 63 6f 6e 66 69 67 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}