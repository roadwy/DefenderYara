
rule Backdoor_Linux_BPFDoor_J_MTB{
	meta:
		description = "Backdoor:Linux/BPFDoor.J!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 45 ff 8b 45 f8 48 98 48 03 45 d8 8b 55 f8 48 63 d2 48 03 55 d8 0f b6 0a 0f b6 55 ff 48 03 55 e8 0f b6 12 31 ca 88 10 83 45 f8 01 } //2
		$a_01_1 = {5b 2b 5d 20 20 20 53 70 61 77 6e 20 73 68 65 6c 6c 20 6f 6b 2e } //1 [+]   Spawn shell ok.
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}