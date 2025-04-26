
rule Trojan_Win32_BotX_RDA_MTB{
	meta:
		description = "Trojan:Win32/BotX.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 74 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}