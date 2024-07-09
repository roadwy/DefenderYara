
rule Backdoor_Linux_Gafgyt_W_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.W!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {05 00 1c 3c ?? ?? 9c 27 21 e0 99 03 e0 ff bd 27 1c 00 bf af 18 00 b0 af 10 00 bc af 52 10 02 24 0c 00 00 00 ?? ?? 99 8f 06 00 e0 10 21 80 40 00 09 f8 20 03 00 00 00 00 10 00 bc 8f 00 00 50 ac ff ff 02 24 1c 00 bf 8f 18 00 b0 8f 08 00 e0 03 20 00 bd 27 } //1
		$a_03_1 = {26 10 22 01 27 18 02 00 21 10 4b 00 26 10 43 00 24 10 4a 00 f8 ff 40 10 04 00 84 24 fc ff 82 ?? ff ff 88 24 fc ff 83 24 fd ff 86 24 03 00 45 14 fe ff 87 24 08 00 e0 03 21 10 60 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}