
rule Trojan_BAT_KillMBR_MK_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 20 00 02 00 00 8d ?? ?? ?? 01 0b 73 20 00 00 0a 0c 08 07 6f ?? ?? ?? 0a 00 06 07 16 07 8e 69 6f ?? ?? ?? 0a 00 00 de 10 } //20
		$a_03_1 = {00 06 07 02 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5f d2 9c 00 07 17 58 0b 07 ?? ?? ?? ?? ?? fe 04 0d 09 2d dd } //10
		$a_81_2 = {5c 5c 5c 5c 2e 5c 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //5 \\\\.\\PhysicalDrive0
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_81_2  & 1)*5) >=35
 
}