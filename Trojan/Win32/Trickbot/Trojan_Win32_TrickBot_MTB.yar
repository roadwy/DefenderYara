
rule Trojan_Win32_TrickBot_MTB{
	meta:
		description = "Trojan:Win32/TrickBot!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 74 24 8b 45 fc 33 d2 f7 75 14 8b 45 08 0f be 0c 10 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 eb cb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}