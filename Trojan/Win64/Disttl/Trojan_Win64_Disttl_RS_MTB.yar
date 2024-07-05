
rule Trojan_Win64_Disttl_RS_MTB{
	meta:
		description = "Trojan:Win64/Disttl.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 41 6e 6f 77 65 7a 20 50 72 6f 78 79 2e 70 64 62 } //01 00  \x64\Release\Anowez Proxy.pdb
		$a_01_1 = {5c 47 72 6f 77 74 6f 70 69 61 5c 63 61 63 68 65 5c 69 74 65 6d 73 2e 64 61 74 } //01 00  \Growtopia\cache\items.dat
		$a_01_2 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 47 72 6f 77 74 6f 70 69 61 5c } //00 00  \AppData\Local\Growtopia\
	condition:
		any of ($a_*)
 
}