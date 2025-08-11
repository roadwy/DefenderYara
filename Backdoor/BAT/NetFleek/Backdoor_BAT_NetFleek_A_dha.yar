
rule Backdoor_BAT_NetFleek_A_dha{
	meta:
		description = "Backdoor:BAT/NetFleek.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 61 64 50 6c 75 67 69 6e 73 } //1 LoadPlugins
		$a_01_1 = {47 65 74 50 6c 75 67 69 6e 73 } //1 GetPlugins
		$a_01_2 = {45 78 65 63 75 74 65 50 6c 75 67 69 6e 73 } //1 ExecutePlugins
		$a_01_3 = {75 70 64 4c 6f 63 61 74 69 6f 6e } //1 updLocation
		$a_01_4 = {2e 00 75 00 73 00 62 00 } //1 .usb
		$a_01_5 = {2e 00 73 00 63 00 72 00 6e 00 } //1 .scrn
		$a_01_6 = {2e 00 73 00 6f 00 63 00 } //1 .soc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}