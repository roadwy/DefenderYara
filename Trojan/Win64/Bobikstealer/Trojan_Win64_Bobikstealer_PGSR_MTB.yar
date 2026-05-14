
rule Trojan_Win64_Bobikstealer_PGSR_MTB{
	meta:
		description = "Trojan:Win64/Bobikstealer.PGSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0c 00 00 "
		
	strings :
		$a_80_0 = {43 37 78 32 4b 70 39 51 6d 4e 34 76 52 38 79 4c 31 63 46 36 77 48 33 64 4a 35 73 42 30 67 54 37 70 56 32 65 5a 61 58 75 } //C7x2Kp9QmN4vR8yL1cF6wH3dJ5sB0gT7pV2eZaXu  10
		$a_80_1 = {56 69 72 74 75 61 6c 42 6f 78 } //VirtualBox  1
		$a_80_2 = {56 4d 77 61 72 65 } //VMware  1
		$a_80_3 = {77 69 72 65 73 68 61 72 6b } //wireshark  1
		$a_80_4 = {74 63 70 76 69 65 77 } //tcpview  1
		$a_80_5 = {70 72 6f 63 65 73 73 68 61 63 6b 65 72 } //processhacker  1
		$a_80_6 = {70 72 6f 63 6d 6f 6e } //procmon  1
		$a_80_7 = {70 72 6f 63 65 78 70 } //procexp  1
		$a_80_8 = {42 4c 4f 43 4b 45 44 20 2d 20 43 49 53 20 63 6f 75 6e 74 72 79 20 64 65 74 65 63 74 65 64 } //BLOCKED - CIS country detected  2
		$a_80_9 = {42 4c 4f 43 4b 45 44 20 2d 20 56 4d 20 64 65 74 65 63 74 65 64 } //BLOCKED - VM detected  2
		$a_80_10 = {43 68 65 63 6b 69 6e 67 20 56 4d 77 61 72 65 20 54 6f 6f 6c 73 20 64 69 72 65 63 74 6f 72 } //Checking VMware Tools director  2
		$a_80_11 = {4b 69 6c 6c 69 6e 67 20 64 65 62 75 67 67 65 72 73 } //Killing debuggers  2
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*2+(#a_80_9  & 1)*2+(#a_80_10  & 1)*2+(#a_80_11  & 1)*2) >=20
 
}