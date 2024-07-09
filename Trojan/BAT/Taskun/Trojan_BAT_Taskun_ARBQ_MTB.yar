
rule Trojan_BAT_Taskun_ARBQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 11 06 07 8e 69 5d 13 07 11 06 08 6f ?? ?? ?? 0a 5d 13 08 07 11 07 91 13 09 08 11 08 6f ?? ?? ?? 0a 13 0a 02 07 11 06 28 ?? ?? ?? 06 13 0b 02 11 09 11 0a 11 0b 28 ?? ?? ?? 06 13 0c 07 11 07 02 11 0c 28 ?? ?? ?? 06 9c 00 11 06 17 59 13 06 11 06 16 fe 04 16 fe 01 13 0d 11 0d 2d a2 } //2
		$a_01_1 = {42 61 74 74 6c 65 73 68 69 70 73 2e 4d 61 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //2 Battleships.MainForm.resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}