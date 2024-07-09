
rule Trojan_Win64_IcedID_HAL_MTB{
	meta:
		description = "Trojan:Win64/IcedID.HAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 d0 48 8b 45 ?? 4c 8d 04 02 8b 45 fc 48 63 d0 48 8b 45 ?? 48 01 d0 44 0f b6 08 8b 4d fc ba } //1
		$a_03_1 = {0f af c2 01 c8 48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 45 fc ?? 8b 45 fc 3b 45 ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}