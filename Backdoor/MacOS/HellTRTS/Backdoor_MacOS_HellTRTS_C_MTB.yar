
rule Backdoor_MacOS_HellTRTS_C_MTB{
	meta:
		description = "Backdoor:MacOS/HellTRTS.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 65 6c 6c 52 61 69 73 65 72 20 68 61 73 20 62 65 65 6e 20 69 6e 73 74 61 6c 6c 65 64 } //2 HellRaiser has been installed
		$a_00_1 = {64 63 68 6b 67 2e 70 65 72 73 6f 2e 77 61 6e 61 64 6f 6f 2e 66 72 } //1 dchkg.perso.wanadoo.fr
		$a_00_2 = {53 4d 54 50 20 47 72 61 62 62 65 72 20 32 2e 30 } //1 SMTP Grabber 2.0
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}