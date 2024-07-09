
rule Trojan_Win32_Trickbot_GB{
	meta:
		description = "Trojan:Win32/Trickbot.GB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {54 68 65 20 74 72 69 63 6b 5c 59 61 6e 64 65 78 44 69 73 6b 5c 50 72 6f 6a 65 63 74 73 5c 42 6f 74 5c 42 6f 74 5f 28 31 30 30 36 29 5f 30 38 2e 31 32 2e 32 30 31 36 5c 42 6f 74 5c 47 65 74 53 79 73 74 65 6d 49 6e 66 6f 5f 73 6f 6c 75 74 69 6f 6e 5c [0-06] 5c 52 65 6c 65 61 73 65 5c 47 65 74 53 79 73 74 65 6d 49 6e 66 6f 2e 70 64 62 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}