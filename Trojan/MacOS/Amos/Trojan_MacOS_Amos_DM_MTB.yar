
rule Trojan_MacOS_Amos_DM_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DM!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 48 83 ec 10 48 89 7d f8 48 8b 7d f8 e8 cb 2d 76 00 48 83 c4 10 5d c3 } //1
		$a_01_1 = {48 8d bd a8 bb ff ff e8 40 2c 32 00 88 85 fc e4 fe ff eb 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}