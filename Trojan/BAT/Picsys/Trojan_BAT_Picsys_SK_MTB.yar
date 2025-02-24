
rule Trojan_BAT_Picsys_SK_MTB{
	meta:
		description = "Trojan:BAT/Picsys.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 07 59 8d 27 00 00 01 0d 02 07 09 16 09 8e 69 28 1d 00 00 0a 06 09 6f 1e 00 00 0a 08 03 8e 69 58 0b 02 03 07 28 04 00 00 06 0c 08 16 fe 04 2c cf } //2
		$a_81_1 = {73 74 75 62 2e 65 78 65 2e 50 72 6f 70 65 72 74 69 65 73 } //2 stub.exe.Properties
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}