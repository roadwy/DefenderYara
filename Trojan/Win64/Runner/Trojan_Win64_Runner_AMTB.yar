
rule Trojan_Win64_Runner_AMTB{
	meta:
		description = "Trojan:Win64/Runner!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {64 6f 63 75 6d 65 6e 74 5c 5f 5c 5f 5c 5f 5c 64 6f 63 75 6d 65 6e 74 2e 62 61 74 } //document\_\_\_\document.bat  2
		$a_80_1 = {64 6f 63 75 6d 65 6e 74 5c 5f 5c 5f 5c 5f } //document\_\_\_  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}