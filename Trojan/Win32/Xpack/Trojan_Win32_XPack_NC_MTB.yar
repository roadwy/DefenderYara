
rule Trojan_Win32_XPack_NC_MTB{
	meta:
		description = "Trojan:Win32/XPack.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 23 38 78 bb 23 ad ?? ?? ?? ?? 20 b5 a4 21 1a 36 14 ?? 34 45 93 03 b8 1b 0c 15 81 09 1f 79 24 } //5
		$a_01_1 = {39 38 74 65 2e 34 79 } //1 98te.4y
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}