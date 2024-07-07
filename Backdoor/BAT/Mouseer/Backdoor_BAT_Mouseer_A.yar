
rule Backdoor_BAT_Mouseer_A{
	meta:
		description = "Backdoor:BAT/Mouseer.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 36 39 61 66 63 63 30 35 2d 61 38 30 35 2d 34 34 62 61 2d 62 32 35 35 2d 36 31 36 63 32 64 32 37 33 30 65 35 } //10 $69afcc05-a805-44ba-b255-616c2d2730e5
		$a_01_1 = {00 64 72 75 6d 73 61 6d 6f 72 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}