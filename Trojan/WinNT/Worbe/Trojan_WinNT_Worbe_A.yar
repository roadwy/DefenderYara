
rule Trojan_WinNT_Worbe_A{
	meta:
		description = "Trojan:WinNT/Worbe.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 0c 56 ff 75 08 ff 15 90 01 02 01 00 eb 05 b8 22 00 00 c0 8b 4d fc 5f 5e e8 90 00 } //1
		$a_00_1 = {6d 00 73 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 } //1 msdefender
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}