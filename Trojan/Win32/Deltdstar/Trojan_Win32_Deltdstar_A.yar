
rule Trojan_Win32_Deltdstar_A{
	meta:
		description = "Trojan:Win32/Deltdstar.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {74 64 73 73 2a 00 00 00 25 73 5c 25 73 } //1
		$a_00_1 = {5c 00 64 00 65 00 76 00 69 00 63 00 65 00 5c 00 6e 00 61 00 6d 00 65 00 64 00 70 00 69 00 70 00 65 00 5c 00 74 00 64 00 73 00 73 00 63 00 6d 00 64 00 00 00 74 00 64 00 73 00 73 00 } //1
		$a_00_2 = {5c 00 72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 72 00 75 00 6e 00 6f 00 6e 00 63 00 65 00 } //1 \registry\machine\software\microsoft\windows\currentversion\runonce
		$a_00_3 = {74 64 73 73 00 00 00 00 5c 5c 3f 5c 67 6c 6f 62 61 6c 72 6f 6f 74 5c 73 79 73 74 65 6d 72 6f 6f 74 5c 73 79 73 74 65 6d 33 32 } //1
		$a_01_4 = {ff d7 68 bc 20 40 00 53 6a 00 ff 15 60 20 40 00 eb 0a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}