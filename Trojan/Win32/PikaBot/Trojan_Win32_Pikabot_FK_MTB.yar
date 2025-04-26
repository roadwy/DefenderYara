
rule Trojan_Win32_Pikabot_FK_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.FK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 02 6a 00 e8 fc fd fa ff 8b 55 cc 03 55 ac 81 ea 53 37 02 00 03 55 e8 2b d0 8b 45 d8 31 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}