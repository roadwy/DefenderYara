
rule Adware_MacOS_SAgnt_A_MTB{
	meta:
		description = "Adware:MacOS/SAgnt.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {c7 45 fc 00 00 00 00 89 7d f8 48 89 75 f0 e8 33 00 00 00 48 8d 35 e6 03 00 00 48 89 f7 48 89 45 e8 b0 00 e8 12 00 00 00 48 8b 7d e8 e8 0f 00 00 00 31 c0 48 83 c4 20 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}