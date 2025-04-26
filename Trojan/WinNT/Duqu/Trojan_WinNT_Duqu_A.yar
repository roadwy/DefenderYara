
rule Trojan_WinNT_Duqu_A{
	meta:
		description = "Trojan:WinNT/Duqu.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 c0 0d 8d 4e 0d 8b d0 2b d1 8b 09 2b 08 3b ca 0f 94 c0 } //1
		$a_03_1 = {8b 44 24 04 81 60 1c 7f ff ff ff 6a 00 c7 46 20 01 00 00 00 ff 15 ?? ?? ?? ?? 6a 01 68 24 10 00 00 } //1
		$a_03_2 = {8b d1 0f af d1 b8 ?? ?? ?? ?? f7 e2 8b c1 69 c0 ?? ?? ?? ?? c1 ea 0c 8d 54 02 01 83 c6 01 33 ca } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}