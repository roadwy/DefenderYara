
rule Trojan_WinNT_Duqu_B{
	meta:
		description = "Trojan:WinNT/Duqu.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 fd 06 13 a8 50 e8 ?? ?? ?? ?? 8d 4c 24 ?? 68 55 87 fe 7a 51 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}