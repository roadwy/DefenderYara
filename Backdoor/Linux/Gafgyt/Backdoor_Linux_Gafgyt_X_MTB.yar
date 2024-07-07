
rule Backdoor_Linux_Gafgyt_X_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.X!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3c 1c 00 05 27 9c 90 01 02 03 99 e0 21 27 bd ff e0 af bf 00 1c af b0 00 18 af bc 00 10 24 02 10 52 00 00 00 0c 8f 99 90 01 02 10 e0 00 06 00 40 80 21 03 20 f8 09 00 00 00 00 8f bc 00 10 ac 50 00 00 24 02 ff ff 8f bf 00 1c 8f b0 00 18 03 e0 00 08 27 bd 00 20 90 00 } //1
		$a_03_1 = {01 22 10 26 00 02 18 27 00 4b 10 21 00 43 10 26 00 4a 10 24 10 40 ff f8 24 84 00 04 90 01 01 82 ff fc 24 88 ff ff 24 83 ff fc 24 86 ff fd 14 45 00 03 24 87 ff fe 03 e0 00 08 00 60 10 21 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}