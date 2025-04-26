
rule Trojan_Win64_Bumblebee_DDD_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.DDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 c1 ea 08 48 8b 05 35 6d 0c 00 89 0d f3 6d 0c 00 8b 88 c4 00 00 00 33 0d 53 6d 0c 00 81 e9 fe e3 15 00 09 0d eb 6d 0c 00 49 63 4f 6c 49 8b 87 ?? ?? ?? ?? 88 14 01 41 ff 47 6c 41 8b 87 ac 00 00 00 8b 0d d4 6d 0c 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}