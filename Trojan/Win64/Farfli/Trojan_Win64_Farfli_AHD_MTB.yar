
rule Trojan_Win64_Farfli_AHD_MTB{
	meta:
		description = "Trojan:Win64/Farfli.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 e9 03 d1 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 69 d2 ?? 00 00 00 2b ca 81 c1 ?? ?? 00 00 69 c9 ?? ?? 00 00 ff 15 } //30
		$a_01_1 = {6e 65 77 20 62 69 67 20 6c 6f 6f 70 20 63 6f 6e 6e 65 63 74 20 25 73 20 25 64 20 2c 73 6c 65 65 70 20 25 64 } //20 new big loop connect %s %d ,sleep %d
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}