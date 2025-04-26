
rule Trojan_Win64_Latot_A_MTB{
	meta:
		description = "Trojan:Win64/Latot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 0b 48 ff c3 88 4c 1a ff 84 c9 } //2
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 46 65 61 74 75 72 65 73 } //2 SOFTWARE\Microsoft\Windows Defender\Features
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 52 65 61 6c 2d 54 69 6d 65 20 50 72 6f 74 65 63 74 69 6f 6e } //2 SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}