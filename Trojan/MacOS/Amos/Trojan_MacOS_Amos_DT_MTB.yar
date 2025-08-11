
rule Trojan_MacOS_Amos_DT_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DT!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 83 ec 20 48 89 7d f8 48 8b 7d f8 48 89 7d f0 e8 77 1f 00 00 a8 01 75 02 eb 0f } //1
		$a_01_1 = {48 8b 7d f0 e8 98 1f 00 00 48 89 45 e8 eb 0d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}