
rule Trojan_Win32_Glupteba_SRP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.SRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 d4 83 c2 01 89 55 d4 8b 45 d4 3b 45 10 73 63 6a 00 ff 15 00 10 41 00 8b 4d d4 81 e1 03 00 00 80 79 05 49 83 c9 fc 41 8b 55 08 0f be 04 0a 8b 4d 0c 03 4d d4 0f be 11 33 c2 88 45 d2 8b 45 0c 03 45 d4 8a 08 88 4d d3 0f be 55 d2 0f be 45 d3 03 d0 8b 4d 0c 03 4d d4 88 11 0f be 55 d3 8b 45 0c 03 45 d4 0f be 08 2b ca 8b 55 0c 03 55 d4 88 0a eb 8c } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}