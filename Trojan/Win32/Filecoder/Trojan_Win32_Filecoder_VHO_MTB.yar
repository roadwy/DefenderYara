
rule Trojan_Win32_Filecoder_VHO_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.VHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {56 8b 45 08 8b 4d 0c 33 f6 46 d3 e6 23 c6 5e 8b e5 5d c2 08 00 } //0a 00 
		$a_01_1 = {89 06 8b 55 cc 8b 4d e0 46 49 } //01 00 
		$a_80_2 = {4d 6a 61 71 67 7a 74 69 20 47 6d 63 6f 72 6b 74 6f 69 20 59 65 68 6f 6c } //Mjaqgzti Gmcorktoi Yehol  01 00 
		$a_80_3 = {4c 64 65 6f 6b 70 20 4d 6e 7a 66 64 20 50 73 66 72 77 65 73 6f } //Ldeokp Mnzfd Psfrweso  00 00 
	condition:
		any of ($a_*)
 
}