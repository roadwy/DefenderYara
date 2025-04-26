
rule Trojan_MacOS_Amos_AX_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AX!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 89 7d f8 48 8b 45 f8 48 8b 0d a5 a4 00 00 48 83 c1 10 48 89 08 5d c3 } //1
		$a_03_1 = {48 83 ec 20 48 89 7d f0 48 89 75 e8 48 8b 7d f0 48 8b 45 e8 48 89 45 e0 e8 ?? ?? ?? ?? 48 89 c1 48 8b 45 e0 48 39 c8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}