
rule Rogue_Win32_Naparb{
	meta:
		description = "Rogue:Win32/Naparb,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 68 79 20 63 61 6e 60 74 20 49 20 72 65 6d 6f 76 65 20 74 68 65 20 76 69 72 75 73 65 73 20 00 ff ff ff ff 90 00 00 00 64 65 74 65 63 74 73 3f 00 } //3
		$a_01_1 = {54 72 6f 6a 61 6e 2e 48 6f 6f 62 6c 6f 6e 67 2e 41 00 } //2
		$a_01_2 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 63 6f 6d 70 72 6f 6d 69 73 65 64 20 62 79 20 68 61 63 6b 65 72 73 2c 20 61 64 77 61 72 65 2c 20 6d 61 6c 77 61 72 65 20 61 6e 64 20 77 6f 72 6d 73 21 } //2 Your computer is compromised by hackers, adware, malware and worms!
		$a_01_3 = {68 61 73 20 64 65 74 65 63 74 65 64 20 73 6f 6d 65 20 73 65 72 69 6f 75 73 20 74 68 72 65 61 74 73 20 74 6f 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 21 } //1 has detected some serious threats to your computer!
		$a_01_4 = {6f 6e 65 20 6f 66 20 74 68 65 20 62 65 73 74 20 61 6e 74 69 76 69 72 75 73 65 73 20 74 6f 64 61 79 3f } //1 one of the best antiviruses today?
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}