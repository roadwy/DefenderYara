
rule Trojan_O97M_Obfuse_JL_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.JL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 72 72 61 79 28 22 40 63 68 64 2e 63 6f 6d 2e 63 6e 22 2c 20 22 40 63 66 69 74 63 2e 63 6f 6d 22 2c 20 22 40 63 67 2e 63 6f 6d 2e 63 6e 22 2c 20 22 40 63 68 64 65 72 2e 63 6f 6d 22 2c 20 22 40 63 68 64 68 6b 2e 63 6f 6d 22 2c 20 22 40 63 68 64 69 2e 61 63 2e 63 6e 22 2c 20 22 40 63 68 64 6f 63 2e 63 6f 6d 2e 63 6e } //1 Array("@chd.com.cn", "@cfitc.com", "@cg.com.cn", "@chder.com", "@chdhk.com", "@chdi.ac.cn", "@chdoc.com.cn
		$a_01_1 = {4c 6f 61 64 20 22 68 74 74 70 3a 2f 2f 31 30 2e 37 39 2e 32 32 2e 31 30 3a 38 30 38 30 2f 3f 65 72 65 66 3d 22 20 26 20 45 6d 61 69 6c } //1 Load "http://10.79.22.10:8080/?eref=" & Email
		$a_01_2 = {26 6d 72 65 66 3d 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 43 6f 6d 70 75 74 65 72 4e 61 6d 65 22 29 20 26 20 22 26 75 72 65 66 3d 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 6e 61 6d 65 22 29 } //1 &mref=" & Environ("ComputerName") & "&uref=" & Environ("Username")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}