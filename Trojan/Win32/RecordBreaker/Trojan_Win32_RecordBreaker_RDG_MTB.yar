
rule Trojan_Win32_RecordBreaker_RDG_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 00 68 00 72 00 6f 00 6d 00 65 00 47 00 72 00 61 00 62 00 62 00 65 00 72 00 28 00 29 00 3a 00 20 00 53 00 65 00 6e 00 64 00 69 00 6e 00 67 00 20 00 25 00 64 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 61 00 6e 00 64 00 20 00 25 00 64 00 20 00 74 00 78 00 74 00 20 00 66 00 69 00 6c 00 65 00 73 00 } //1 ChromeGrabber(): Sending %d files and %d txt files
		$a_03_1 = {81 ef 04 00 00 00 66 33 d1 2b d6 85 e2 8b 17 f9 f8 f5 33 d3 c1 ca 02 66 3b c8 f8 81 f2 90 01 04 4a f5 c1 ca 02 0f ca 66 3b e0 f9 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}