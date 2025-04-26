
rule Trojan_MacOS_KCSteal_C_MTB{
	meta:
		description = "Trojan:MacOS/KCSteal.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 53 50 48 89 fb 48 8b 35 58 3b 00 00 48 8d 15 f1 23 00 00 ff 15 e3 22 00 00 48 89 d8 48 83 c4 08 5b 5d c3 } //1
		$a_01_1 = {55 48 89 e5 53 50 48 89 fb 48 83 c7 28 31 f6 e8 71 00 00 00 48 8d 7b 20 31 f6 e8 66 00 00 00 48 8d 7b 18 31 f6 e8 5b 00 00 00 48 8d 7b 10 31 f6 e8 50 00 00 00 48 83 c3 08 48 89 df 31 f6 48 83 c4 08 5b 5d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}