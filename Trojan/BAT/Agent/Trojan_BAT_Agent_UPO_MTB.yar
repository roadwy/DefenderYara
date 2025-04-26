
rule Trojan_BAT_Agent_UPO_MTB{
	meta:
		description = "Trojan:BAT/Agent.UPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {42 72 6f 77 73 65 72 20 73 65 72 76 69 63 65 } //1 Browser service
		$a_81_1 = {68 74 74 70 3a 2f 2f 31 37 36 2e 31 31 31 2e 31 37 34 2e 31 30 37 2f 41 70 69 2f 47 65 74 54 61 73 6b 2f } //1 http://176.111.174.107/Api/GetTask/
		$a_81_2 = {68 74 74 70 3a 2f 2f 31 37 36 2e 31 31 31 2e 31 37 34 2e 31 30 37 2f 63 68 72 6f 6d 65 2e 7a 69 70 } //1 http://176.111.174.107/chrome.zip
		$a_81_3 = {55 47 46 49 4f 45 48 46 47 49 45 46 49 55 4b 55 46 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 UGFIOEHFGIEFIUKUF.Properties.Resources
		$a_81_4 = {43 6c 69 65 6e 74 48 6f 73 74 2e 65 78 65 } //1 ClientHost.exe
		$a_81_5 = {77 65 6f 75 66 67 6f 77 65 69 66 68 69 75 77 65 66 } //1 weoufgoweifhiuwef
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}