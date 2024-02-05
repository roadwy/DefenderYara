
rule Virus_Win32_Grum_C{
	meta:
		description = "Virus:Win32/Grum.C,SIGNATURE_TYPE_PEHSTR,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_01_0 = {60 e8 00 00 00 00 5d 81 ed 12 25 9c 00 33 c9 33 c0 33 db 99 ac 8a c8 3c 0f 74 0f 66 81 7e ff cd 20 75 0a 46 ad e9 01 01 00 00 ac fe c4 d1 e8 8a 84 05 4f 26 9c 00 72 03 c1 e8 04 83 e0 0f 93 80 fb 0e 0f 84 f2 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}