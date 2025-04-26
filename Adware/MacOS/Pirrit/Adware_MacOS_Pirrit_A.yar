
rule Adware_MacOS_Pirrit_A{
	meta:
		description = "Adware:MacOS/Pirrit.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 50 69 72 72 69 74 } //2 HKEY_LOCAL_MACHINE\SOFTWARE\Pirrit
		$a_00_1 = {70 72 6f 6a 65 63 74 73 2f 70 69 72 72 69 74 2f 6d 61 63 6f 73 2f 50 72 6f 78 79 53 65 72 76 65 72 } //1 projects/pirrit/macos/ProxyServer
		$a_00_2 = {74 68 65 63 6c 6f 75 64 73 65 72 76 69 63 65 73 2e 6e 65 74 } //1 thecloudservices.net
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}