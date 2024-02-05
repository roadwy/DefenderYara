
rule Trojan_Win32_Pony_AN_MTB{
	meta:
		description = "Trojan:Win32/Pony.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {39 c3 ac 25 2d b0 f7 85 6b 6c 6f 67 19 15 8c dd ab 78 fa bf 4f 57 49 52 c1 51 13 44 e4 5a 0b 49 91 53 1b 57 43 87 0a 55 42 ec 33 6f b8 32 25 75 1d 75 01 57 17 5a 08 4d fb bd 13 49 df 9e 05 50 0a 50 0b 51 71 } //00 00 
	condition:
		any of ($a_*)
 
}