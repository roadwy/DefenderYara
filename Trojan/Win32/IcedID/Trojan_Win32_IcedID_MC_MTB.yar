
rule Trojan_Win32_IcedID_MC_MTB{
	meta:
		description = "Trojan:Win32/IcedID.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {f9 cd 02 8c 9e 90 9c 92 97 91 8c 9f 47 64 9e 80 31 84 88 86 8f 8d 90 83 ec 8f 8a 94 85 88 84 8a bb b9 a4 b7 90 b3 b6 a8 b1 bc b0 be b7 b5 a8 bb } //0a 00 
		$a_01_1 = {30 b6 81 eb fc d8 91 f5 73 45 43 46 da de 8f e6 74 57 52 4c 5d 50 5c 52 53 51 4c 5f 78 5b 5e 40 19 01 48 46 03 4c 54 43 69 91 0c 08 45 48 44 4a } //05 00 
		$a_01_2 = {4a 00 69 00 70 00 6f 00 6b 00 65 00 72 00 } //05 00 
		$a_01_3 = {4b 00 69 00 6f 00 70 00 66 00 6a 00 65 00 6a 00 64 00 67 00 79 00 6b 00 } //01 00 
		$a_01_4 = {66 72 6d 57 65 62 42 72 6f 77 73 65 72 } //01 00 
		$a_01_5 = {74 78 74 50 61 73 73 57 6f 72 64 } //00 00 
	condition:
		any of ($a_*)
 
}