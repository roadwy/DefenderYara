
rule Trojan_BAT_Spynoon_AE_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 21 00 07 09 11 04 6f ?? 01 00 0a 13 08 08 12 08 28 ?? 01 00 0a 6f ?? 01 00 0a 00 11 04 17 58 13 04 00 11 04 07 6f ?? 01 00 0a fe 04 13 09 11 09 2d cf 09 17 58 0d 00 09 07 6f } //4
		$a_01_1 = {4d 00 79 00 46 00 74 00 70 00 43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 MyFtpClient.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}