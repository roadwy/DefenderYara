
rule Trojan_Win32_Dropper_AA_MTB{
	meta:
		description = "Trojan:Win32/Dropper.AA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe 81 00 01 00 00 0f b6 b9 00 01 00 00 8d 5b 01 0f b6 04 0f 00 81 01 01 00 00 0f b6 b1 01 01 00 00 8a 14 0f 0f b6 04 0e 88 04 0f 88 14 0e 0f b6 81 01 01 00 00 0f b6 91 00 01 00 00 0f b6 04 08 02 04 0a 8b 55 f8 0f b6 c0 0f b6 04 08 32 44 1a ff ff 4d fc 88 43 ff 75 a7 } //01 00 
		$a_01_1 = {8a 14 37 8b c7 25 3f 00 00 80 79 05 48 83 c8 c0 40 8b 4d fc 47 0f b6 04 08 02 c2 02 d8 0f b6 cb 0f b6 04 31 88 44 37 ff 88 14 31 81 ff 00 01 00 00 7c cd } //00 00 
	condition:
		any of ($a_*)
 
}