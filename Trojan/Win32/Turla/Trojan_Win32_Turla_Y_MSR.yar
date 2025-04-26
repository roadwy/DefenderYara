
rule Trojan_Win32_Turla_Y_MSR{
	meta:
		description = "Trojan:Win32/Turla.Y!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 2a 3a 38 30 2f 4f 57 41 2f 4f 41 42 2f } //1 http://*:80/OWA/OAB/
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 2a 3a 34 34 33 2f 4f 57 41 2f 4f 41 42 2f } //1 https://*:443/OWA/OAB/
		$a_01_2 = {64 00 63 00 6f 00 6d 00 6e 00 65 00 74 00 73 00 72 00 76 00 2e 00 63 00 70 00 70 00 } //1 dcomnetsrv.cpp
		$a_01_3 = {5c 44 65 76 65 6c 6f 70 5c 73 70 73 5c 6e 65 75 72 6f 6e } //1 \Develop\sps\neuron
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}