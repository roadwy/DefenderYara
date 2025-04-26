
rule Trojan_Win64_Posdrop_A_dha{
	meta:
		description = "Trojan:Win64/Posdrop.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 48 65 6c 70 41 73 73 69 73 74 61 6e 74 5c 62 74 69 64 2e 64 61 74 } //1 \Microsoft\HelpAssistant\btid.dat
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 48 65 6c 70 41 73 73 69 73 74 61 6e 74 5c 62 74 64 61 74 61 2e 74 78 74 } //1 \Microsoft\HelpAssistant\btdata.txt
		$a_01_2 = {6e 73 2e 61 6b 61 6d 61 69 31 38 31 31 2e 63 6f 6d } //1 ns.akamai1811.com
		$a_01_3 = {61 70 69 2e 69 70 69 66 79 2e 6f 72 67 } //1 api.ipify.org
		$a_01_4 = {54 65 6d 70 5c 6d 65 6d 73 63 72 70 2e 73 74 70 } //1 Temp\memscrp.stp
		$a_01_5 = {2e 73 74 6f 70 70 65 64 } //1 .stopped
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}