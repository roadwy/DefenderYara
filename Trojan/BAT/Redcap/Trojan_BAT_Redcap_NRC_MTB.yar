
rule Trojan_BAT_Redcap_NRC_MTB{
	meta:
		description = "Trojan:BAT/Redcap.NRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 be 00 00 0a 16 13 18 dd ?? ?? 00 00 11 13 7b ?? ?? 00 04 11 0b 6f ?? ?? 00 0a 26 14 13 0c 72 ?? ?? 00 70 73 ?? ?? 00 0a 13 0d 11 07 13 0e } //5
		$a_01_1 = {46 69 72 65 66 6f 78 50 61 73 73 77 6f 72 64 47 72 61 62 62 65 72 2e 65 78 65 } //1 FirefoxPasswordGrabber.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Redcap_NRC_MTB_2{
	meta:
		description = "Trojan:BAT/Redcap.NRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 1a 00 00 01 13 04 7e ?? 00 00 04 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 04 16 11 05 6f ?? 00 00 0a 13 06 09 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 09 6f ?? 00 00 0a 2c bb } //5
		$a_01_1 = {63 70 70 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //1 cppExecutablePath
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}