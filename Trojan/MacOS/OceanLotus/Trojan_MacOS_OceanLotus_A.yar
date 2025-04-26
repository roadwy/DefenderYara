
rule Trojan_MacOS_OceanLotus_A{
	meta:
		description = "Trojan:MacOS/OceanLotus.A,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 61 70 70 6c 65 2e 6d 61 72 63 6f 61 67 65 6e 74 2e 76 6f 69 63 65 69 6e 73 74 61 6c 6c 65 72 64 } //2 com.apple.marcoagent.voiceinstallerd
		$a_00_1 = {2f 4c 69 62 72 61 72 79 2f 55 73 65 72 20 50 68 6f 74 6f 73 } //1 /Library/User Photos
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}