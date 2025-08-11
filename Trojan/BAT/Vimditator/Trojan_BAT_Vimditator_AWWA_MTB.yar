
rule Trojan_BAT_Vimditator_AWWA_MTB{
	meta:
		description = "Trojan:BAT/Vimditator.AWWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {1f 09 0b 05 04 07 5d 9a 28 ?? ?? 00 0a 03 28 ?? 02 00 06 28 ?? ?? 00 0a 0a 2b 00 06 2a } //3
		$a_03_1 = {02 03 66 5f 02 66 03 5f 60 8c ?? 00 00 01 0a 2b 00 06 2a } //2
		$a_03_2 = {03 08 02 03 08 91 08 04 28 ?? ?? 00 06 9c 08 17 d6 0c 08 07 31 ea } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=7
 
}