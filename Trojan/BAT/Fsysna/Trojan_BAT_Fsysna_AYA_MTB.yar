
rule Trojan_BAT_Fsysna_AYA_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 00 72 00 6c 00 6f 00 67 00 6f 00 6e 00 75 00 69 00 2e 00 72 00 75 00 } //2 mrlogonui.ru
		$a_01_1 = {73 76 63 68 6f 73 74 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 svchost.Form1.resources
		$a_00_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 } //1 DisableAntiSpyware
		$a_00_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 } //1 DisableAntiVirus
		$a_00_4 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 61 00 6c 00 74 00 69 00 6d 00 65 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00 } //1 DisableRealtimeMonitoring
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}