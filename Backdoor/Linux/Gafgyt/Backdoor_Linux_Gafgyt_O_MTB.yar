
rule Backdoor_Linux_Gafgyt_O_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.O!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {05 00 1c 3c 90 01 02 9c 27 21 e0 99 03 e0 ff bd 27 1c 00 bf af 18 00 b0 af 10 00 bc af 52 10 02 24 0c 00 00 00 90 01 02 99 8f 06 00 e0 10 21 80 40 00 09 f8 20 03 00 00 00 00 10 00 bc 8f 00 00 50 ac ff ff 02 24 1c 00 bf 8f 18 00 b0 8f 08 00 e0 03 20 00 bd 27 90 00 } //02 00 
		$a_03_1 = {3c 1c 00 05 27 9c 90 01 02 03 99 e0 21 27 bd ff e0 af bf 00 1c af b0 00 18 af bc 00 10 24 02 10 52 00 00 00 0c 8f 99 90 01 02 10 e0 00 06 00 40 80 21 03 20 f8 09 00 00 00 00 8f bc 00 10 ac 50 00 00 24 02 ff ff 8f bf 00 1c 8f b0 00 18 03 e0 00 08 27 bd 00 20 90 00 } //01 00 
		$a_01_2 = {55 44 50 52 41 57 } //01 00  UDPRAW
		$a_01_3 = {62 6f 74 2e 6d 69 70 73 } //00 00  bot.mips
	condition:
		any of ($a_*)
 
}