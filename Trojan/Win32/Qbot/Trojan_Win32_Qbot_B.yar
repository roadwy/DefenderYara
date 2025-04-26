
rule Trojan_Win32_Qbot_B{
	meta:
		description = "Trojan:Win32/Qbot.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 37 52 38 4a 37 64 38 6e 70 69 7c 44 61 35 75 39 23 6d 54 4f 77 79 64 48 34 2e 70 64 62 } //1 .7R8J7d8npi|Da5u9#mTOwydH4.pdb
		$a_01_1 = {74 79 70 65 64 77 65 72 65 4a 34 6a 64 32 61 73 70 65 63 74 73 55 52 4c 73 } //1 typedwereJ4jd2aspectsURLs
		$a_01_2 = {6e 55 73 79 6e 63 68 72 6f 6e 69 7a 65 74 68 65 74 68 65 69 72 61 64 69 73 70 6c 61 79 69 6e 67 53 65 70 74 65 6d 62 65 72 5a } //1 nUsynchronizethetheiradisplayingSeptemberZ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}