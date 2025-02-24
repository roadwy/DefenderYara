
rule Trojan_MacOS_Amos_CQ_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CQ!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 89 ff e8 ?? ?? ?? ?? 4c 89 f7 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 31 c0 48 81 c4 c0 00 00 00 5b 41 5c 41 5e 41 5f 5d c3 } //1
		$a_03_1 = {55 48 89 e5 53 50 48 89 fb e8 ?? ?? ?? ?? 48 8b 05 63 c7 00 00 48 83 c0 10 48 89 03 48 83 c4 08 5b 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}