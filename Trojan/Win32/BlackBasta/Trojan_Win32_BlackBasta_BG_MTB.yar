
rule Trojan_Win32_BlackBasta_BG_MTB{
	meta:
		description = "Trojan:Win32/BlackBasta.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 03 6b d2 19 8b c1 2b c2 8a 90 90 ?? ?? ?? ?? 8d 34 39 32 14 2e 83 c1 01 3b cb 88 16 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}