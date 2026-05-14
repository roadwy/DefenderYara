
rule Trojan_Win32_Agent_AMTB{
	meta:
		description = "Trojan:Win32/Agent!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_80_0 = {63 75 72 6c 20 2d 73 20 2d 6f 20 6e 75 6c 20 2d 48 20 22 58 2d 4b 65 79 3a 20 39 32 63 44 6f 70 70 33 6a 74 68 34 39 39 73 64 61 32 6e 6e 34 61 6a 6e 73 64 22 20 2d 48 20 22 58 2d 55 73 65 72 } //curl -s -o nul -H "X-Key: 92cDopp3jth499sda2nn4ajnsd" -H "X-User  6
	condition:
		((#a_80_0  & 1)*6) >=6
 
}