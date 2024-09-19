
rule Trojan_Win64_Barys_GPA_MTB{
	meta:
		description = "Trojan:Win64/Barys.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 69 70 68 65 72 2d 30 2e 33 2e 30 5c 73 72 63 5c 73 74 72 65 61 6d 2e 72 73 } //4 cipher-0.3.0\src\stream.rs
		$a_01_1 = {73 72 63 5c 6d 69 73 63 5c 64 69 73 63 6f 72 64 2e 72 73 } //3 src\misc\discord.rs
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3) >=7
 
}