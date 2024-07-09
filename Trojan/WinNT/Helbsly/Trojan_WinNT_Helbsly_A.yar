
rule Trojan_WinNT_Helbsly_A{
	meta:
		description = "Trojan:WinNT/Helbsly.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 39 5d d8 76 50 66 81 7d d8 ff 00 73 48 8b 46 44 3b 05 ?? ?? ?? ?? 75 75 8b 46 28 } //1
		$a_01_1 = {74 09 81 7d 1c 03 00 12 00 74 07 8b c7 e9 48 01 00 00 85 ff 0f 8c 3d 01 00 00 83 65 d0 00 6a 05 59 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}