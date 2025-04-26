
rule TrojanDownloader_Win64_Rugmi_EC_MTB{
	meta:
		description = "TrojanDownloader:Win64/Rugmi.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 35 33 26 af 22 48 89 c2 48 c1 c2 07 31 c2 0f b7 c2 48 01 c8 c3 } //5
		$a_01_1 = {48 89 c2 48 d1 c2 48 31 c2 48 89 d0 48 c1 c0 02 31 d0 0f b7 c0 48 01 c8 c3 } //5
		$a_01_2 = {72 73 2d 73 68 65 6c 6c 2d 6d 61 69 6e 5c 6b 75 6e 64 61 6c 69 6e 69 } //1 rs-shell-main\kundalini
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}