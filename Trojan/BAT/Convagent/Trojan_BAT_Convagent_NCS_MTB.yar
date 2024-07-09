
rule Trojan_BAT_Convagent_NCS_MTB{
	meta:
		description = "Trojan:BAT/Convagent.NCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7e 03 00 00 04 14 fe 01 0a 06 2c 22 00 72 ?? ?? ?? 70 d0 ?? ?? ?? 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 73 ?? ?? ?? 0a 0b 07 80 ?? ?? ?? 04 00 7e ?? ?? ?? 04 0c 2b 00 08 2a } //5
		$a_01_1 = {78 76 69 64 2e 46 6f 72 6d 31 } //1 xvid.Form1
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}