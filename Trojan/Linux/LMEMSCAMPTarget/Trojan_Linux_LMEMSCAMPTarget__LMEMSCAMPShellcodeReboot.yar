
rule Trojan_Linux_LMEMSCAMPTarget__LMEMSCAMPShellcodeReboot{
	meta:
		description = "Trojan:Linux/LMEMSCAMPTarget!!LMEMSCAMPShellcodeReboot,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {54 68 69 73 20 69 73 20 61 6e 20 6c 6d 65 6d 73 20 74 65 73 74 20 73 69 67 } //1 This is an lmems test sig
		$a_00_1 = {55 73 65 64 20 66 6f 72 20 65 6e 67 69 6e 65 20 43 41 4d 50 20 66 75 6e 63 74 69 6f 6e 61 6c 20 74 65 73 74 69 6e 67 } //2 Used for engine CAMP functional testing
		$a_01_2 = {ba dc fe 21 43 be 69 19 12 28 bf ad de e1 fe b0 a9 0f 05 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_01_2  & 1)*3) >=3
 
}