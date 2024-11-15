
rule Trojan_BAT_Zusy_SK_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 65 72 76 65 72 31 2e 65 78 65 } //2 server1.exe
		$a_81_1 = {73 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 server.Resources.resources
		$a_81_2 = {24 63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 37 38 34 39 34 } //2 $cc7fad03-816e-432c-9b92-001f2d378494
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}