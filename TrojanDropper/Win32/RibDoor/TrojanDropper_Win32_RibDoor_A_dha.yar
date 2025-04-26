
rule TrojanDropper_Win32_RibDoor_A_dha{
	meta:
		description = "TrojanDropper:Win32/RibDoor.A!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 43 38 41 34 32 42 33 38 30 43 30 34 39 30 31 41 36 37 32 30 39 34 31 35 31 41 34 30 32 30 32 } //1 EC8A42B380C04901A672094151A40202
		$a_01_1 = {68 74 74 70 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f } //1 http://pastebin.com/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}