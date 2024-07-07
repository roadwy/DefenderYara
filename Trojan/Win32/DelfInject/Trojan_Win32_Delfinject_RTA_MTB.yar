
rule Trojan_Win32_Delfinject_RTA_MTB{
	meta:
		description = "Trojan:Win32/Delfinject.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 f7 c7 00 f9 74 90 01 01 8b 45 90 01 01 8b 40 90 01 01 8b 55 90 01 01 8b 52 90 01 01 03 02 66 81 e7 ff 0f 0f b7 d7 03 c2 8b 55 90 01 01 8b 52 90 01 01 01 10 92 92 29 c8 29 c8 8d 0c 13 83 06 02 4b 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}