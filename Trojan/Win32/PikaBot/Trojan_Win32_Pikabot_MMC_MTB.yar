
rule Trojan_Win32_Pikabot_MMC_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.MMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b 40 0c } //1
		$a_01_1 = {8d 40 0c 8b 00 8b 40 18 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}