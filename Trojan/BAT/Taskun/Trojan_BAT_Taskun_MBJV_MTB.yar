
rule Trojan_BAT_Taskun_MBJV_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 61 00 64 00 00 0f 52 00 61 00 77 00 32 00 4d 00 47 00 46 00 00 0b 6a 00 59 00 2e 00 6a 00 63 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65 00 00 17 49 00 6e 00 70 00 75 } //1
		$a_01_1 = {38 35 37 33 2d 33 65 31 36 63 37 66 33 38 61 35 39 } //1 8573-3e16c7f38a59
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}