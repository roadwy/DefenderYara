
rule Trojan_Win32_Glupteba_ED_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 30 39 30 43 30 6c 30 c0 30 dc 30 1c 31 4c 31 63 31 6c 31 75 31 8f 31 ac 31 d8 31 e1 31 fc 31 28 32 01 33 1d 33 3e 33 a9 33 b4 33 d5 33 dc 33 d6 34 39 35 44 35 14 36 21 36 2f 36 39 36 4b 36 50 36 5d 36 6c 36 9b 36 2e 37 3a 37 4d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}